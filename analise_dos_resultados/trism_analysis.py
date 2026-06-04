import argparse
import ast
import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from scipy.stats import (
    mannwhitneyu
)

warnings.filterwarnings("ignore")

# load data
def load_data(off_file, on_file):

    df_off = pd.read_csv(off_file)
    df_on = pd.read_csv(on_file)

    df_off["trism_enabled"] = False
    df_on["trism_enabled"] = True

    return pd.concat([df_off, df_on], ignore_index=True)

# aux
def safe_list_len(value):

    if pd.isna(value):
        return 0

    try:
        parsed = ast.literal_eval(str(value))
        return len(parsed) if isinstance(parsed, list) else 0
    except:
        return 0
    
# feature engineering
def create_features(df):
    df["token_ratio"] = df["output_tokens"] / (df["input_tokens"] + 1)

    df["score_gap"] = (
        df["score"] - df["min_score_required"]
    )

    df["blocked"] = df["blocked"].astype(bool)

    df["blocked_int"] = (
        df["blocked"].astype(int)
    )

    df["passed_int"] = (
        df["passed"].astype(int)
    )

    df["num_violations"] = (
        df["violations"].apply(safe_list_len)
    )

    df["num_owasp_categories"] = (
        df["owasp_categories"].apply(safe_list_len)
    )

    df["num_policies_triggered"] = (
        df["policies_triggered"].apply(safe_list_len)
    )

    # Functional Success
    df["functional_success"] = (
        df["score"] >= df["min_score_required"]
    )

    # Security Success
    df["security_success"] = (
        (df["num_violations"] > 0)
        &
        (df["num_owasp_categories"] > 0)
    )

    # Governance Success (ModelOps)
    df["governance_success"] = (
        (df["blocked_int"] == 1)
        &
        (df["num_policies_triggered"] > 0)
    )

    return df

# statistical analysis
def descriptive_analysis(df):

    metrics = [
        "latency_ms",
        "score",
        "trust",
        "input_tokens",
        "output_tokens",
        "token_ratio",
        "score_gap",
        "num_violations",
        "num_owasp_categories",
        "num_policies_triggered"
    ]

    summary = (
        df.groupby("trism_enabled")[metrics]
        .agg(["mean", "std", "median"])
        .round(4)
    )

    print(summary)

    summary.to_csv(
        "descriptive_results.csv"
    )

    return summary

# success rate analysis
def success_analysis(df):

    summary = (
        df.groupby("trism_enabled")
        [
            [
                "functional_success",
                "security_success",
                "governance_success",
                "passed_int",
                "blocked_int"
            ]
        ]
        .mean()
        .round(4)
    )

    print(summary)

    summary.to_csv(
        "success_metrics.csv"
    )

    return summary

# Hypothesis testing
def hypothesis_test(df):

    metrics = [
        "latency_ms",
        "score",
        "trust",
        "token_ratio",
        "score_gap",
        "num_violations",
        "num_owasp_categories",
        "num_policies_triggered"
    ]

    results = []

    off = df[df["trism_enabled"] == False]
    on  = df[df["trism_enabled"] == True]

    for metric in metrics:

        stat, p = mannwhitneyu(
            off[metric],
            on[metric],
            alternative="two-sided"
        )

        results.append({
            "metric": metric,
            "test": "Mann-Whitney",
            "p_value": p,
            "significant": p < 0.05
        })

    results = pd.DataFrame(results)

    print(results)

    results.to_csv(
        "hypothesis_test.csv",
        index=False
    )

    return results
    
# statistical evaluation
def run_hypothesis_tests(df):

    metrics = [
        "latency_ms",
        "score",
        "trust",
        "token_ratio",
        "score_gap",
        "num_violations",
        "num_owasp_categories",
        "num_policies_triggered"
    ]

    results = []

    for metric in metrics:
        results.append(
            hypothesis_test(df, metric)
        )

    results = pd.DataFrame(results)

    results.to_csv(
        "hypothesis_tests.csv",
        index=False
    )

    print(results)

    return results

# evaluation modelops
def modelops_analysis(df):

    summary = (
        df.groupby("trism_enabled")
        [
            [
                "score",
                "trust",
                "latency_ms",
                "passed_int"
            ]
        ]
        .mean()
        .round(4)
    )

    print(summary)

    summary.to_csv(
        "modelops_analysis.csv"
    )

    return summary


def plot_modelops_success(df):

    metrics = [
        "functional_success",
        "security_success",
        "governance_success"
    ]

    summary = (
        df.groupby("trism_enabled")[metrics]
        .mean()
    )

    summary.index = ["OFF", "ON"]

    ax = summary.plot(
        kind="bar",
        figsize=(8,5)
    )

    for container in ax.containers:
        ax.bar_label(
            container,
            fmt="%.3f"
        )

    plt.ylabel("Success Rate")
    plt.xlabel("Environment")
    plt.title(
        "ModelOps Success Metrics"
    )

    plt.tight_layout()

    plt.savefig(
        "modelops_success_metrics.png",
        dpi=300
    )

    plt.close()

# main
def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--off",
        required=True
    )

    parser.add_argument(
        "--on",
        required=True
    )

    args = parser.parse_args()

    df = load_data(args.off, args.on)
    
    df.rename(columns={"confidence": "trust"}, inplace=True)

    df = create_features(df)
    
    df.rename(columns={"confidence": "trust"}, inplace=True)

    descriptive_analysis(df)

    success_analysis(df)

    modelops_analysis(df)

    hypothesis_test(df)

    plot_modelops_success(df)

    df.to_csv(
        "modelops_results.csv",
        index=False
    )

    print("\nArquivos gerados:")
    print("descriptive_analysis.csv")
    print("success_analysis.csv")
    print("hypothesis_tests.csv")
    print("modelops_analysis.csv")
    print("evaluation_results.csv")
    
    
if __name__ == "__main__":
    main()