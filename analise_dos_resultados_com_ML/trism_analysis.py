import argparse
import warnings
import ast
import numpy as np
import pandas as pd
from scipy.stats import entropy
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.mixture import GaussianMixture
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score, davies_bouldin_score, calinski_harabasz_score
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

def load_data(off_file, on_file):
    df_off = pd.read_csv(off_file)
    df_on = pd.read_csv(on_file)
    df_off["trism_enabled"] = False
    df_on["trism_enabled"] = True
    df = pd.concat([df_off, df_on], ignore_index=True)
    return df

def safe_list_len(s):
    if pd.isna(s) or str(s).strip() == "":
        return 0
    try:
        val = ast.literal_eval(str(s))
        return len(val) if isinstance(val, list) else 0
    except:
        return 0

def create_features(df):
    df["token_ratio"] = df["output_tokens"] / (df["input_tokens"] + 1)
    df["score_gap"] = df["score"] - df["min_score_required"]
    df["blocked"] = df["blocked"].astype(bool)
    df["blocked_int"] = df["blocked"].astype(int)
    df["passed_int"] = df["passed"].astype(int)
    df["num_violations"] = df["violations"].apply(safe_list_len)
    df["num_owasp_categories"] = df["owasp_categories"].apply(safe_list_len)
    df["num_policies_triggered"] = df["policies_triggered"].apply(safe_list_len)
    df["functional_success"] = df["score"] >= df["min_score_required"]
    df["security_success"] = (df["num_violations"] == 0) & (df["num_owasp_categories"] == 0)
    df["governance_success"] = (df["blocked"] == False) & (df["num_violations"] == 0) & (df["num_policies_triggered"] == 0)
    return df

def get_features():
    return [
        "latency_ms", "score", "confidence", "input_tokens", "output_tokens",
        "token_ratio", "score_gap", "num_violations", "num_owasp_categories",
        "num_policies_triggered", "blocked_int"
    ]

def normalize_data(df, features):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df[features])
    return X_scaled, scaler

def apply_pca(X_scaled):
    n_comp = min(7, X_scaled.shape[1])
    pca = PCA(n_components=n_comp, random_state=42)
    X_pca = pca.fit_transform(X_scaled)
    print("\n===== PCA =====")
    for i, var in enumerate(pca.explained_variance_ratio_):
        print(f"PC{i+1}: {var:.4f}")
    print(f"\nVariância acumulada: {np.sum(pca.explained_variance_ratio_):.4f}")
    return X_pca, pca

def find_best_k(X_pca):
    best_k = 2
    best_score = -1
    print("\n===== BUSCANDO K =====")
    for k in range(2, 11):
        if X_pca.shape[0] < k:
            continue
        km = KMeans(n_clusters=k, random_state=42, n_init=20)
        labels = km.fit_predict(X_pca)
        score = silhouette_score(X_pca, labels)
        print(f"K={k} Silhouette={score:.4f}")
        if score > best_score:
            best_score = score
            best_k = k
    print(f"\nMelhor K: {best_k}")
    return best_k

def hybrid_clustering(X_pca, n_clusters):
    print("\n===== KMEANS =====")
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=20)
    kmeans.fit(X_pca)
    initial_means = kmeans.cluster_centers_
    print("===== GMM =====")
    gmm = GaussianMixture(n_components=n_clusters, covariance_type="diag", reg_covar=1e-2, means_init=initial_means, random_state=42)
    labels = gmm.fit_predict(X_pca)
    probs = gmm.predict_proba(X_pca)
    return labels, probs, kmeans, gmm

def calculate_uncertainty(df, probs):
    df["uncertainty"] = 1 - probs.max(axis=1)
    df["entropy"] = [entropy(p) for p in probs]
    return df

def detect_anomalies(df, X_pca):
    iso = IsolationForest(contamination=0.05, random_state=42)
    preds = iso.fit_predict(X_pca)
    df["anomaly"] = (preds == -1)
    return df

def clustering_metrics(X_pca, labels):
    sil = silhouette_score(X_pca, labels)
    dbi = davies_bouldin_score(X_pca, labels)
    chi = calinski_harabasz_score(X_pca, labels)
    print("\n===== MÉTRICAS =====")
    print(f"Silhouette: {sil:.4f}")
    print(f"Davies-Bouldin: {dbi:.4f}")
    print(f"Calinski-Harabasz: {chi:.4f}")

def compare_trism(df):
    print("\n===== COMPARAÇÃO TRISM =====")
    summary = df.groupby("trism_enabled")[["uncertainty", "entropy", "anomaly", "functional_success", "security_success", "governance_success", "score", "confidence"]].mean().round(4)
    print(summary)
    summary.to_csv("trism_comparison.csv")
    return summary

def cluster_distribution(df):
    dist = pd.crosstab(df["cluster"], df["trism_enabled"], normalize="columns")
    print("\n===== DISTRIBUIÇÃO =====")
    print(dist)
    dist.to_csv("cluster_distribution.csv")
    return dist

def cluster_summary(df, features):
    summary = df.groupby("cluster")[features].mean().round(4)
    summary.to_csv("cluster_summary.csv")
    return summary

def plot_pca_by_trism(df):
    for trism_value in [False, True]:
        subset = df[df["trism_enabled"] == trism_value]
        plt.figure(figsize=(10, 6))
        plt.scatter(subset["PC1"], subset["PC2"], c=subset["cluster"], alpha=0.7)
        label = "ON" if trism_value else "OFF"
        plt.title(f"PCA + GMM - TRiSM {label}")
        plt.xlabel("PC1")
        plt.ylabel("PC2")
        plt.colorbar(label="Cluster")
        plt.tight_layout()
        plt.savefig(f"pca_trism_{label}.png", dpi=300)
        plt.close()

def pillar_analysis(df):
    if "pillar" not in df.columns:
        print("\nAviso: Coluna 'pillar' não encontrada. Pulando análise por pilar.")
        return None
    pillar_summary = df.groupby(["pillar", "trism_enabled"])[["score", "confidence", "functional_success", "security_success", "governance_success", "blocked_int", "uncertainty", "entropy"]].mean().round(4)
    pillar_summary.to_csv("pillar_analysis.csv")
    print("\n===== PILAR =====")
    print(pillar_summary)
    return pillar_summary

def plot_success_metrics(df):
    if "pillar" not in df.columns:
        print("Aviso: Coluna 'pillar' não encontrada. Não é possível gerar gráficos por pilar.")
        return
    metrics = ["functional_success", "security_success", "governance_success"]
    for metric in metrics:
        summary = df.groupby(["pillar", "trism_enabled"])[metric].mean().unstack()
        summary.columns = ["OFF", "ON"] if False in summary.columns else summary.columns
        ax = summary.plot(kind="bar", figsize=(12, 6))
        
        for container in ax.containers:
            ax.bar_label(container, fmt='%.3f', fontsize=9, padding=3)
        
        plt.title(f"{metric} por Pilar")
        plt.ylabel("Taxa de Sucesso")
        plt.xlabel("Pilar")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(f"{metric}_by_pillar.png", dpi=300)
        plt.close()

def plot_score_by_pillar(df):
    if "pillar" not in df.columns:
        return
    pillars = df["pillar"].dropna().unique()
    for pillar in pillars:
        subset = df[df["pillar"] == pillar]
        off = subset[subset["trism_enabled"] == False]["score"]
        on = subset[subset["trism_enabled"] == True]["score"]
        plt.figure(figsize=(8, 5))
        plt.boxplot([off, on], labels=["OFF", "ON"])
        plt.title(f"Score - {pillar}")
        plt.ylabel("Score")
        plt.tight_layout()
        plt.savefig(f"score_{pillar}.png", dpi=300)
        plt.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--off", required=True)
    parser.add_argument("--on", required=True)
    args = parser.parse_args()
    print("\nCarregando dados...")
    df = load_data(args.off, args.on)
    print(f"Total registros: {len(df)}")
    df = create_features(df)
    features = get_features()
    X_scaled, scaler = normalize_data(df, features)
    X_pca, pca = apply_pca(X_scaled)
    df["PC1"] = X_pca[:, 0]
    df["PC2"] = X_pca[:, 1]
    best_k = find_best_k(X_pca)
    labels, probs, kmeans, gmm = hybrid_clustering(X_pca, best_k)
    df["cluster"] = labels
    df = calculate_uncertainty(df, probs)
    df = detect_anomalies(df, X_pca)
    clustering_metrics(X_pca, labels)
    compare_trism(df)
    cluster_distribution(df)
    cluster_summary(df, features)
    pillar_analysis(df)
    plot_pca_by_trism(df)
    plot_success_metrics(df)
    plot_score_by_pillar(df)
    df.to_csv("hybrid_gmm_results.csv", index=False)
    print("\n===== ARQUIVOS GERADOS =====")
    print("hybrid_gmm_results.csv")
    print("trism_comparison.csv")
    print("cluster_distribution.csv")
    print("cluster_summary.csv")
    print("pillar_analysis.csv")
    print("pca_trism_OFF.png")
    print("pca_trism_ON.png")
    print("functional_success_by_pillar.png")
    print("security_success_by_pillar.png")
    print("governance_success_by_pillar.png")

if __name__ == "__main__":
    main()