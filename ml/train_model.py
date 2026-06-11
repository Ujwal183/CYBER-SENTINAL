"""
🛡️ Cyber Sentinel - ML Training Pipeline
Trains ensemble intrusion detection model using simulated network features.
"""
import os, json, pickle, warnings
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, IsolationForest, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
warnings.filterwarnings("ignore")

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    from lightgbm import LGBMClassifier
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False

FEATURE_NAMES = [
    "protocol_type","src_port","dst_port","packet_size","flow_duration",
    "fwd_packets","bwd_packets","flow_bytes_per_sec","flow_packets_per_sec",
    "syn_flag","ack_flag","fin_flag","rst_flag","psh_flag","urg_flag",
    "connection_rate","entropy_score","payload_length","header_length","ttl",
    "window_size","ip_reputation_score","port_frequency","unique_dst_ports","bytes_ratio"
]
ATTACK_TYPES = ["Normal","DDoS","Port Scan","Brute Force","Botnet","SQL Injection","Web Attack","DoS Slowloris"]
MODEL_DIR = Path(__file__).parent / "models"
DATA_DIR = Path(__file__).parent / "data"

def _gen_rows(n, label, overrides):
    base = {"protocol_type":0,"src_port":0,"dst_port":80,"packet_size":500,"flow_duration":5,
            "fwd_packets":10,"bwd_packets":10,"flow_bytes_per_sec":5000,"flow_packets_per_sec":10,
            "syn_flag":0,"ack_flag":1,"fin_flag":0,"rst_flag":0,"psh_flag":0,"urg_flag":0,
            "connection_rate":5,"entropy_score":4,"payload_length":300,"header_length":20,"ttl":64,
            "window_size":30000,"ip_reputation_score":0.1,"port_frequency":3,"unique_dst_ports":2,"bytes_ratio":0.5}
    rows = []
    for _ in range(n):
        row = base.copy()
        for k, v in overrides.items():
            row[k] = v() if callable(v) else v
        rows.append(row)
    return rows, [label]*n

def generate_synthetic_dataset(n=50000):
    np.random.seed(42)
    rn = np.random
    all_rows, all_labels = [], []
    profiles = {
        "Normal": (0.60, {"protocol_type":lambda:rn.choice([0,1,2]),"src_port":lambda:rn.randint(1024,65535),"dst_port":lambda:rn.choice([80,443,22,53]),"packet_size":lambda:rn.normal(500,200),"flow_duration":lambda:rn.exponential(5),"fwd_packets":lambda:rn.randint(1,50),"bwd_packets":lambda:rn.randint(1,50),"flow_bytes_per_sec":lambda:rn.normal(5000,2000),"flow_packets_per_sec":lambda:rn.normal(10,5),"syn_flag":lambda:rn.choice([0,1],p=[.7,.3]),"ack_flag":lambda:rn.choice([0,1],p=[.3,.7]),"connection_rate":lambda:rn.normal(5,2),"entropy_score":lambda:rn.uniform(3.5,5),"ip_reputation_score":lambda:rn.uniform(0,0.2),"unique_dst_ports":lambda:rn.randint(1,5),"bytes_ratio":lambda:rn.uniform(.3,.7)}),
        "DDoS": (0.10, {"dst_port":lambda:rn.choice([80,443]),"packet_size":lambda:rn.normal(100,30),"flow_duration":lambda:rn.exponential(.5),"fwd_packets":lambda:rn.randint(100,10000),"bwd_packets":lambda:rn.randint(0,5),"flow_bytes_per_sec":lambda:rn.normal(100000,50000),"flow_packets_per_sec":lambda:rn.normal(5000,2000),"syn_flag":1,"ack_flag":0,"connection_rate":lambda:rn.normal(500,200),"entropy_score":lambda:rn.uniform(.5,2),"ip_reputation_score":lambda:rn.uniform(.6,1),"unique_dst_ports":1,"bytes_ratio":lambda:rn.uniform(.9,1)}),
        "Port Scan": (0.08, {"dst_port":lambda:rn.randint(1,65535),"packet_size":lambda:rn.normal(60,10),"flow_duration":lambda:rn.exponential(.1),"fwd_packets":lambda:rn.randint(1,3),"bwd_packets":lambda:rn.randint(0,2),"syn_flag":1,"rst_flag":lambda:rn.choice([0,1],p=[.3,.7]),"connection_rate":lambda:rn.normal(200,100),"entropy_score":lambda:rn.uniform(6,8),"payload_length":0,"unique_dst_ports":lambda:rn.randint(50,1000),"bytes_ratio":lambda:rn.uniform(.95,1)}),
        "Brute Force": (0.07, {"dst_port":lambda:rn.choice([22,3389,21]),"packet_size":lambda:rn.normal(200,50),"fwd_packets":lambda:rn.randint(5,50),"bwd_packets":lambda:rn.randint(5,50),"syn_flag":1,"ack_flag":1,"psh_flag":1,"connection_rate":lambda:rn.normal(50,20),"entropy_score":lambda:rn.uniform(2,4),"ip_reputation_score":lambda:rn.uniform(.4,.8),"unique_dst_ports":1}),
        "Botnet": (0.05, {"dst_port":lambda:rn.choice([6667,8080,4444]),"flow_duration":lambda:rn.exponential(30),"fwd_packets":lambda:rn.randint(10,200),"bwd_packets":lambda:rn.randint(10,200),"syn_flag":1,"ack_flag":1,"psh_flag":1,"entropy_score":lambda:rn.uniform(4,7),"ip_reputation_score":lambda:rn.uniform(.5,.9),"unique_dst_ports":lambda:rn.randint(2,10)}),
        "SQL Injection": (0.03, {"dst_port":lambda:rn.choice([80,443,3306]),"packet_size":lambda:rn.normal(800,300),"syn_flag":1,"ack_flag":1,"fin_flag":1,"psh_flag":1,"entropy_score":lambda:rn.uniform(5,7.5),"payload_length":lambda:rn.normal(500,200),"ip_reputation_score":lambda:rn.uniform(.3,.6)}),
        "Web Attack": (0.04, {"dst_port":lambda:rn.choice([80,443,8080]),"packet_size":lambda:rn.normal(600,250),"syn_flag":1,"ack_flag":1,"psh_flag":1,"entropy_score":lambda:rn.uniform(5.5,7.5),"payload_length":lambda:rn.normal(400,150)}),
        "DoS Slowloris": (0.03, {"dst_port":80,"packet_size":lambda:rn.normal(40,10),"flow_duration":lambda:rn.exponential(60),"fwd_packets":lambda:rn.randint(50,500),"bwd_packets":lambda:rn.randint(0,5),"syn_flag":1,"ack_flag":0,"connection_rate":lambda:rn.normal(300,100),"entropy_score":lambda:rn.uniform(.5,2),"payload_length":lambda:rn.normal(10,5),"ip_reputation_score":lambda:rn.uniform(.5,.9),"unique_dst_ports":1}),
    }
    for label, (frac, overrides) in profiles.items():
        cnt = int(n * frac)
        r, l = _gen_rows(cnt, label, overrides)
        all_rows.extend(r); all_labels.extend(l)
    df = pd.DataFrame(all_rows)
    df["label"] = all_labels
    for c in df.select_dtypes(include=[np.number]).columns:
        df[c] = df[c].clip(lower=0)
    return df

def evaluate_model(y_true, y_pred, y_proba, le):
    m = {"accuracy":float(accuracy_score(y_true,y_pred)),"precision":float(precision_score(y_true,y_pred,average="weighted",zero_division=0)),"recall":float(recall_score(y_true,y_pred,average="weighted",zero_division=0)),"f1_score":float(f1_score(y_true,y_pred,average="weighted",zero_division=0)),"confusion_matrix":confusion_matrix(y_true,y_pred).tolist()}
    try: m["roc_auc"]=float(roc_auc_score(y_true,y_proba,multi_class="ovr",average="weighted"))
    except: m["roc_auc"]=None
    return m

def train_models():
    print("🛡️ Cyber Sentinel - ML Training Pipeline\n" + "="*60)
    MODEL_DIR.mkdir(parents=True, exist_ok=True); DATA_DIR.mkdir(parents=True, exist_ok=True)
    dp = DATA_DIR/"training_data.csv"
    if dp.exists():
        df = pd.read_csv(dp)
    else:
        df = generate_synthetic_dataset(50000); df.to_csv(dp, index=False)
    print(f"Dataset: {df.shape}, Classes:\n{df['label'].value_counts()}")
    X = df[FEATURE_NAMES].values
    le = LabelEncoder(); y = le.fit_transform(df["label"])
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    sc = StandardScaler(); X_tr_s = sc.fit_transform(X_tr); X_te_s = sc.transform(X_te)
    results = {}
    # Random Forest
    print("\n🌲 Random Forest..."); rf = RandomForestClassifier(n_estimators=200,max_depth=20,n_jobs=-1,random_state=42,class_weight="balanced"); rf.fit(X_tr_s,y_tr); results["Random Forest"]=evaluate_model(y_te,rf.predict(X_te_s),rf.predict_proba(X_te_s),le); print(f"  Acc: {results['Random Forest']['accuracy']:.4f}")
    # XGBoost
    if HAS_XGB:
        print("🚀 XGBoost..."); xgb=XGBClassifier(n_estimators=200,max_depth=10,learning_rate=0.1,n_jobs=-1,random_state=42,eval_metric="mlogloss",use_label_encoder=False); xgb.fit(X_tr_s,y_tr); results["XGBoost"]=evaluate_model(y_te,xgb.predict(X_te_s),xgb.predict_proba(X_te_s),le); print(f"  Acc: {results['XGBoost']['accuracy']:.4f}")
    # LightGBM
    if HAS_LGBM:
        print("⚡ LightGBM..."); lgbm=LGBMClassifier(n_estimators=200,max_depth=10,n_jobs=-1,random_state=42,verbose=-1); lgbm.fit(X_tr_s,y_tr); results["LightGBM"]=evaluate_model(y_te,lgbm.predict(X_te_s),lgbm.predict_proba(X_te_s),le); print(f"  Acc: {results['LightGBM']['accuracy']:.4f}")
    # Isolation Forest
    print("🔍 Isolation Forest..."); iso=IsolationForest(n_estimators=200,contamination=0.15,n_jobs=-1,random_state=42); iso.fit(X_tr_s)
    # Ensemble
    print("🧬 Ensemble Hybrid..."); ests=[("rf",rf)]
    if HAS_XGB: ests.append(("xgb",xgb))
    if HAS_LGBM: ests.append(("lgbm",lgbm))
    ens=VotingClassifier(estimators=ests,voting="soft",n_jobs=-1); ens.fit(X_tr_s,y_tr); results["Ensemble Hybrid"]=evaluate_model(y_te,ens.predict(X_te_s),ens.predict_proba(X_te_s),le); print(f"  Acc: {results['Ensemble Hybrid']['accuracy']:.4f}")
    fi = dict(zip(FEATURE_NAMES, rf.feature_importances_.tolist()))
    bundle = {"ensemble":ens,"random_forest":rf,"isolation_forest":iso,"scaler":sc,"label_encoder":le,"feature_names":FEATURE_NAMES,"attack_types":ATTACK_TYPES,"feature_importance":fi,"results":results,"trained_at":datetime.now().isoformat(),"training_samples":len(X_tr),"test_samples":len(X_te)}
    if HAS_XGB: bundle["xgboost"]=xgb
    if HAS_LGBM: bundle["lightgbm"]=lgbm
    with open(MODEL_DIR/"ensemble_model.pkl","wb") as f: pickle.dump(bundle,f)
    with open(MODEL_DIR/"training_results.json","w") as f: json.dump(results,f,indent=2)
    print("\n" + "="*60 + "\n📊 RESULTS")
    for n,m in results.items(): print(f"  {n}: Acc={m['accuracy']:.4f} F1={m['f1_score']:.4f}")
    print("✅ Training complete!")
    return bundle

if __name__ == "__main__":
    train_models()
