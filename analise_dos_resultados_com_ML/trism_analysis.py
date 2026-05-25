"""
TRiSM Hybrid Clustering Analysis
================================

Pipeline:
1. Carrega datasets OFF e ON
2. Engenharia de atributos
3. Normalização
4. PCA (7 componentes)
5. Escolha automática de K pelo Silhouette
6. K-Means
7. GMM inicializado pelos centroides do K-Means
8. Cálculo de incerteza
9. Cálculo de entropia
10. Isolation Forest
11. Métricas de clusterização
12. Comparação TRiSM ON x OFF
13. Exportação dos resultados

Uso:

python trism_hybrid_analysis.py \
    --off audit_data_off.csv \
    --on audit_data_on.csv
"""

import argparse
import warnings

import numpy as np
import pandas as pd

from scipy.stats import entropy
from scipy.stats import mannwhitneyu

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.mixture import GaussianMixture
from sklearn.ensemble import IsolationForest

from sklearn.metrics import (
    silhouette_score,
    davies_bouldin_score,
    calinski_harabasz_score
)

import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

def load_data(off_file, on_file):

    df_off = pd.read_csv(off_file)
    df_on = pd.read_csv(on_file)

    df_off["trism_enabled"] = False
    df_on["trism_enabled"] = True

    df = pd.concat(
        [df_off, df_on],
        ignore_index=True
    )

    return df

def create_features(df):

    df["token_ratio"] = (
        df["output_tokens"] /
        (df["input_tokens"] + 1)
    )

    df["score_gap"] = (
        df["score"] -
        df["min_score_required"]
    )

    df["blocked_int"] = (
        df["blocked"]
        .astype(int)
    )

    df["passed_int"] = (
        df["passed"]
        .astype(int)
    )

    return df

def get_features():

    return [
        "latency_ms",
        "score",
        "confidence",
        "input_tokens",
        "output_tokens",
        "token_ratio",
        "score_gap"
    ]

def normalize_data(df, features):

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(
        df[features]
    )

    return X_scaled, scaler

def apply_pca(X_scaled):

    pca = PCA(
        n_components=7,
        random_state=42
    )

    X_pca = pca.fit_transform(
        X_scaled
    )

    print("\nVariância explicada PCA:")

    for i, var in enumerate(
        pca.explained_variance_ratio_
    ):
        print(
            f"PC{i+1}: {var:.4f}"
        )

    print(
        f"\nVariância acumulada: "
        f"{np.sum(pca.explained_variance_ratio_):.4f}"
    )

    return X_pca, pca

def find_best_k(X_pca):

    best_k = None
    best_score = -1

    print("\nBuscando melhor K...")

    for k in range(2, 11):

        km = KMeans(
            n_clusters=k,
            random_state=42,
            n_init=20
        )

        labels = km.fit_predict(
            X_pca
        )

        score = silhouette_score(
            X_pca,
            labels
        )

        print(
            f"K={k} -> "
            f"Silhouette={score:.4f}"
        )

        if score > best_score:

            best_score = score
            best_k = k

    print(
        f"\nMelhor K = {best_k}"
    )

    return best_k

def hybrid_clustering(
        X_pca,
        n_clusters
):

    print(
        "\nExecutando K-Means..."
    )

    kmeans = KMeans(
        n_clusters=n_clusters,
        random_state=42,
        n_init=20
    )

    kmeans.fit(X_pca)

    initial_means = (
        kmeans.cluster_centers_
    )

    print(
        "Executando GMM..."
    )

    gmm = GaussianMixture(
        n_components=n_clusters,
        covariance_type="full",
        means_init=initial_means,
        random_state=42
    )

    labels = gmm.fit_predict(
        X_pca
    )

    probs = gmm.predict_proba(
        X_pca
    )

    return (
        labels,
        probs,
        kmeans,
        gmm
    )

def calculate_uncertainty(
        df,
        probs
):

    df["uncertainty"] = (
        1 -
        probs.max(axis=1)
    )

    df["entropy"] = [

        entropy(p)

        for p in probs
    ]

    return df

def detect_anomalies(
        df,
        X_pca
):

    iso = IsolationForest(
        contamination=0.05,
        random_state=42
    )

    preds = iso.fit_predict(
        X_pca
    )

    df["anomaly"] = (
        preds == -1
    )

    return df

def clustering_metrics(
        X_pca,
        labels
):

    sil = silhouette_score(
        X_pca,
        labels
    )

    dbi = davies_bouldin_score(
        X_pca,
        labels
    )

    chi = calinski_harabasz_score(
        X_pca,
        labels
    )

    print("\n===== MÉTRICAS =====")

    print(
        f"Silhouette: {sil:.4f}"
    )

    print(
        f"Davies-Bouldin: {dbi:.4f}"
    )

    print(
        f"Calinski-Harabasz: {chi:.4f}"
    )

    return {

        "silhouette": sil,
        "davies_bouldin": dbi,
        "calinski_harabasz": chi
    }

def compare_trism(df):

    print(
        "\n===== COMPARAÇÃO TRiSM ====="
    )

    summary = (

        df.groupby(
            "trism_enabled"
        )[

            [
                "uncertainty",
                "entropy",
                "anomaly"
            ]

        ]

        .agg(
            ["mean", "std"]
        )
    )

    print(summary)

    summary.to_csv(
        "trism_comparison.csv"
    )

    off_unc = df.loc[
        df["trism_enabled"] == False,
        "uncertainty"
    ]

    on_unc = df.loc[
        df["trism_enabled"] == True,
        "uncertainty"
    ]

    stat, pvalue = mannwhitneyu(
        off_unc,
        on_unc
    )

    print(
        "\nMann-Whitney"
    )

    print(
        f"Statistic = {stat:.4f}"
    )

    print(
        f"P-value   = {pvalue:.8f}"
    )

    return summary

def cluster_distribution(df):

    dist = pd.crosstab(

        df["cluster"],

        df["trism_enabled"],

        normalize="columns"
    )

    print(
        "\n===== DISTRIBUIÇÃO DOS CLUSTERS ====="
    )

    print(dist)

    dist.to_csv(
        "cluster_distribution.csv"
    )

    return dist

def cluster_summary(
        df,
        features
):

    summary = (

        df.groupby(
            "cluster"
        )[features]

        .mean()

        .round(4)
    )

    summary.to_csv(
        "cluster_summary.csv"
    )

    return summary


def plot_clusters(X_pca,labels):

    plt.figure(figsize=(10, 6))
    plt.scatter(
        X_pca[:, 0],
        X_pca[:, 1],
        c=labels,
        alpha=0.7
    )

    plt.title("PCA + KMeans + GMM")
    plt.xlabel("PC1")
    plt.ylabel("PC2")
    plt.colorbar(label="Cluster")
    plt.tight_layout()

    plt.savefig("hybrid_clusters.png",dpi=300)
    plt.close()

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--off",required=True)
    parser.add_argument("--on",required=True)

    args = parser.parse_args()

    print("\nCarregando dados...")

    df = load_data(args.off,args.on)

    print(f"Total registros: {len(df)}")

    df = create_features(df)
    features = get_features()
    X_scaled, scaler = normalize_data(df,features)
    X_pca, pca = apply_pca(X_scaled)
    best_k = find_best_k(X_pca)

    (
        labels,
        probs,
        kmeans,
        gmm

    ) = hybrid_clustering(
        X_pca,
        best_k
    )

    df["cluster"] = labels
    df = calculate_uncertainty(df,probs)
    df = detect_anomalies(df,X_pca)

    clustering_metrics(X_pca,labels)
    compare_trism(df)
    cluster_distribution(df)
    
    cluster_summary(df,features)
    plot_clusters(X_pca,labels)

    df.to_csv(
        "hybrid_gmm_results.csv",
        index=False
    )

    print("\nArquivos gerados:")
    print(" - hybrid_gmm_results.csv")
    print(" - trism_comparison.csv")
    print(" - cluster_distribution.csv")
    print(" - cluster_summary.csv")
    print(" - hybrid_clusters.png")

if __name__ == "__main__":
    main()