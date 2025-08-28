# cyber_dash_app_fixed.py
# A robust, error-hardened Dash app for the Cybersecurity IDS dashboard.
# Changes vs original:
# - Robust CSV loading with timestamp parsing and fallbacks
# - Label normalization to handle 'Benign'/'Attack' or 0/1 values consistently
# - Safe handling when columns are missing; creates placeholder columns as needed
# - Removed unused imports
# - Minor UI polish and clearer status messages

import os
import pandas as pd
from datetime import datetime, timedelta

import dash
from dash import Dash, html, dcc, Input, Output, State, dash_table
import plotly.express as px
import plotly.graph_objects as go

DATA_PATH = os.environ.get("CYBER_DASH_DATA", "dashboard_data.csv")

REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "protocol", "bytes",
    "Label", "model_score", "attack_type", "country"
]


def _ensure_required_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Guarantee required columns exist to avoid runtime errors.
    If missing, create reasonable defaults so the app still runs.
    """
    df = df.copy()

    # timestamp
    if "timestamp" not in df.columns:
        # Create synthetic timestamps if missing
        now = datetime.now()
        df["timestamp"] = [now - timedelta(seconds=15*i) for i in range(len(df))][::-1]
    else:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        # Replace NaT with a forward/back fill then current time
        if df["timestamp"].isna().any():
            df["timestamp"] = df["timestamp"].fillna(method="ffill").fillna(method="bfill")
            df["timestamp"] = df["timestamp"].fillna(datetime.now())

    # src_ip / dst_ip
    for col in ["src_ip", "dst_ip"]:
        if col not in df.columns:
            df[col] = "0.0.0.0"
        df[col] = df[col].astype(str)

    # protocol
    if "protocol" not in df.columns:
        df["protocol"] = "TCP"
    df["protocol"] = df["protocol"].astype(str)

    # bytes
    if "bytes" not in df.columns:
        df["bytes"] = 0
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).astype(int)

    # Label normalization -> string "Benign"/"Attack"
    if "Label" not in df.columns:
        df["Label"] = "Benign"
    # Handle 0/1 or text
    def norm_label(x):
        try:
            # numeric-like
            if str(x).strip() in {"0", "1"}:
                return "Attack" if str(x).strip() == "1" else "Benign"
        except Exception:
            pass
        s = str(x).strip().lower()
        if s == "attack":
            return "Attack"
        if s == "benign" or s == "benign":
            return "Benign"
        # Any other category considered Attack for safety, or default to Benign?
        # We'll default to Attack only if clearly malicious keywords appear
        if any(k in s for k in ["dos", "scan", "bruteforce", "bot", "infil", "mal", "attack"]):
            return "Attack"
        return "Benign"

    df["Label"] = df["Label"].map(norm_label)

    # model_score (0..1)
    if "model_score" not in df.columns:
        # heuristic: benign low, attack higher
        df["model_score"] = df["Label"].map({"Benign": 0.2, "Attack": 0.8})
    df["model_score"] = pd.to_numeric(df["model_score"], errors="coerce").fillna(0.0)

    # attack_type
    if "attack_type" not in df.columns:
        df["attack_type"] = df["Label"].map({"Benign": "None", "Attack": "Unknown"})
    df["attack_type"] = df["attack_type"].astype(str)

    # country
    if "country" not in df.columns:
        df["country"] = "NA"
    df["country"] = df["country"].astype(str)

    return df


def load_data() -> pd.DataFrame:
    # Read CSV safely
    if not os.path.exists(DATA_PATH):
        # Create a tiny placeholder DataFrame if the file is missing, to avoid crashing
        df = pd.DataFrame({
            "timestamp": [datetime.now() - timedelta(minutes=i) for i in range(30)][::-1],
            "src_ip": ["192.168.1.%d" % (i % 255) for i in range(30)],
            "dst_ip": ["10.0.0.%d" % (i % 255) for i in range(30)],
            "protocol": ["TCP"]*30,
            "bytes": [0]*30,
            "Label": ["Benign"]*25 + ["Attack"]*5,
            "model_score": [0.1]*25 + [0.9]*5,
            "attack_type": ["None"]*25 + ["DoS"]*5,
            "country": ["NA"]*30,
        })
        return _ensure_required_columns(df)

    # Normal load path
    df = pd.read_csv(DATA_PATH)
    df = _ensure_required_columns(df)

    # Derived column for convenience
    df["is_attack"] = (df["Label"].str.lower() == "attack").astype(int)
    return df


app = Dash(__name__, title="Cyber Threat Monitor")
server = app.server

app.layout = html.Div([
    html.H1("Cybersecurity IDS Dashboard", style={"textAlign": "center"}),

    html.Div([
        dcc.Input(
            id="search-box",
            type="text",
            placeholder="Search IP / domain / subnet (e.g., 192.168.1.0/24)",
            style={"width": "60%"}
        ),
        html.Button("Search", id="search-btn"),
        html.Span(id="search-status", style={"marginLeft": "12px"}),
    ], style={"display": "flex", "justifyContent": "center", "gap": "8px", "marginBottom": "12px"}),

    html.Div([
        dcc.Dropdown(
            id="protocol-filter",
            options=[{"label": p, "value": p} for p in ["All", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]],
            value="All",
            clearable=False,
            style={"width": "220px"}
        ),
        dcc.DatePickerRange(
            id="date-range",
            display_format="YYYY-MM-DD",
        ),
        dcc.Interval(id="refresh-interval", interval=15_000, n_intervals=0),  # 15s auto-refresh
    ], style={"display": "flex", "gap": "16px", "justifyContent": "center", "margin": "8px"}),

    html.Div([
        dcc.Graph(id="traffic-by-protocol"),
        dcc.Graph(id="top-malicious-ips"),
        dcc.Graph(id="detection-rates"),
        dcc.Graph(id="intrusion-time-series"),
    ], style={"display": "grid", "gridTemplateColumns": "1fr", "gap": "16px", "maxWidth": "1200px", "margin": "0 auto"}),

    html.H3("Logs (filtered)"),
    dash_table.DataTable(
        id="logs-table",
        page_size=15,
        style_table={"maxHeight": "400px", "overflowY": "auto"},
        filter_action="native",
        sort_action="native",
        columns=[{"name": c, "id": c} for c in [
            "timestamp", "src_ip", "dst_ip", "protocol", "bytes", "Label", "model_score", "attack_type", "country"
        ]],
    ),
])


def subnet_mask(ip: str, subnet: str) -> bool:
    """Return True if ip is inside subnet (CIDR).
    Supports simple IPv4 strings. Returns False on any parsing error.
    """
    try:
        import ipaddress
        net = ipaddress.ip_network(subnet, strict=False)
        return ipaddress.ip_address(ip) in net
    except Exception:
        return False


def apply_filters(df: pd.DataFrame, protocol: str, start_date, end_date, search_text: str):
    dff = df.copy()
    if protocol and protocol != "All":
        dff = dff[dff["protocol"] == protocol]

    # Normalize possible string dates from DatePickerRange
    if start_date:
        try:
            start_dt = pd.to_datetime(start_date)
            dff = dff[dff["timestamp"] >= start_dt]
        except Exception:
            pass
    if end_date:
        try:
            end_dt = pd.to_datetime(end_date)
            dff = dff[dff["timestamp"] <= end_dt]
        except Exception:
            pass

    if search_text and isinstance(search_text, str) and len(search_text.strip()) > 0:
        s = search_text.strip()
        if "/" in s:
            mask = dff["src_ip"].apply(lambda ip: subnet_mask(ip, s)) | dff["dst_ip"].apply(lambda ip: subnet_mask(ip, s))
        else:
            # simple contains; could be IP or domain substring
            mask = dff["src_ip"].str.contains(s, na=False) | dff["dst_ip"].str.contains(s, na=False)
        dff = dff[mask]

    return dff


@app.callback(
    Output("traffic-by-protocol", "figure"),
    Output("top-malicious-ips", "figure"),
    Output("detection-rates", "figure"),
    Output("intrusion-time-series", "figure"),
    Output("logs-table", "data"),
    Output("search-status", "children"),
    Input("refresh-interval", "n_intervals"),
    Input("protocol-filter", "value"),
    Input("date-range", "start_date"),
    Input("date-range", "end_date"),
    Input("search-btn", "n_clicks"),
    State("search-box", "value"),
)

def update_dashboard(_, protocol, start_date, end_date, __, search_text):
    df = load_data()

    dff = apply_filters(df, protocol, start_date, end_date, search_text)

    # 1) Traffic by Protocol (stacked benign vs attack)
    if dff.empty:
        fig_proto = go.Figure()
    else:
        proto_grp = dff.groupby(["protocol", "Label"]).size().reset_index(name="count")
        fig_proto = px.bar(proto_grp, x="protocol", y="count", color="Label", barmode="stack",
                           title="Traffic by Protocol (Benign vs Attack)")

    # 2) Top Malicious IPs (source)
    if dff.empty:
        fig_ips = go.Figure()
    else:
        top_ips = (
            dff[dff["Label"].str.lower() == "attack"].groupby("src_ip").size().nlargest(10).reset_index(name="attempts")
        )
        fig_ips = px.bar(top_ips, x="src_ip", y="attempts", title="Top Malicious Source IPs (Top 10)")

    # 3) Detection Rates (Benign vs Attack)
    det = dff["Label"].value_counts().reindex(["Benign", "Attack"]).fillna(0)
    fig_det = go.Figure(data=[go.Pie(labels=det.index, values=det.values, hole=0.4)])
    fig_det.update_layout(title="Detection Rates")

    # 4) Time Series of Intrusion Events
    if dff.empty:
        fig_ts = go.Figure()
    else:
        ts = dff.copy()
        ts["date_min"] = ts["timestamp"].dt.floor("min")
        ts_attack = ts[ts["Label"].str.lower() == "attack"].groupby("date_min").size().reset_index(name="attacks")
        fig_ts = px.line(ts_attack, x="date_min", y="attacks", title="Intrusion Events Over Time")

    # Table data
    table_cols = [c for c in REQUIRED_COLUMNS if c in dff.columns]
    table_data = (
        dff.sort_values("timestamp", ascending=False)[table_cols].head(500).to_dict("records")
        if not dff.empty else []
    )

    # Status message
    status = ""
    if search_text and (len(table_data) == 0):
        status = "No results for your query."
    elif search_text:
        status = f"Showing {len(table_data)} rows for query."

    return fig_proto, fig_ips, fig_det, fig_ts, table_data, status


if __name__ == "__main__":
    # Run: python cyber_dash_app_fixed.py
    # Optional: set data path with env var CYBER_DASH_DATA=path/to/dashboard_data.csv
    app.run(debug=True, host="127.0.0.1", port=8050)

