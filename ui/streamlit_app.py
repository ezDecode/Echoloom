import os
import time
import streamlit as st
from .client import chat as api_chat, set_api_config

st.set_page_config(page_title="Echoloom Chat", page_icon="💬", layout="wide")

# Inject Google Font and dark theme CSS
st.markdown(
	"""
	<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,200..800;1,200..800&display=swap" rel="stylesheet">
	<style>
	:root { --fg:#ffffff; --bg:#000000; --bg2:#0e0e0e; --accent:#6EE7F9; --muted:#9CA3AF; }
	html, body, [data-testid="stAppViewContainer"] { background-color: var(--bg)!important; color: var(--fg)!important; font-family: 'Plus Jakarta Sans', system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif!important; }
	.badge { display:inline-block; padding:4px 8px; border-radius:9999px; background:#1f2937; border:1px solid #374151; color:#e5e7eb; font-size:12px; margin-right:6px; }
	.bubble { border-radius:16px; padding:12px 14px; margin:6px 0; max-width: 900px; }
	.bubble.user { background:#111827; border:1px solid #1f2937; }
	.bubble.bot { background:#0b1320; border:1px solid #1f2937; }
	.meta { color: var(--muted); font-size:12px; margin-top:4px; }
	.hr { height:1px; background:#1f2937; margin:12px 0; }
	.stTextInput input { background-color: var(--bg2)!important; color: var(--fg)!important; border:1px solid #222!important; }
	.stButton button { background: linear-gradient(90deg, #111, #333)!important; color: var(--fg)!important; border:1px solid #333!important; }
	</style>
	""",
	unsafe_allow_html=True,
)

# Sidebar configuration
with st.sidebar:
	st.header("Settings")
	api_url = st.text_input("API URL", os.getenv("API_URL", "http://localhost:8000"))
	api_key = st.text_input("API Key", os.getenv("API_KEY", "dev-key-123"))
	if st.button("Apply"):
		set_api_config(api_url, api_key)
		st.success("Applied API settings")
	st.markdown("---")
	if st.button("Clear chat"):
		st.session_state.history = []
		st.rerun()

st.title("Echoloom Chat 💬")

if "history" not in st.session_state:
	st.session_state.history = []

col_input, col_meta = st.columns([3, 1])

with col_input:
	with st.form("chat-form", clear_on_submit=True):
		msg = st.text_input("Your message", key="msg", placeholder="Type a message...")
		send = st.form_submit_button("Send")

	if send and msg.strip():
		with st.spinner("Thinking..."):
			start = time.time()
			resp = api_chat(msg)
			elapsed = time.time() - start
			# append user and bot messages
			st.session_state.history.append({"role":"user","text":msg,"ts":time.time()})
			st.session_state.history.append({"role":"bot","text":resp.get("answer","(no answer)"),"ts":time.time(),"meta":resp})
			st.toast(f"Response in {elapsed:.2f}s", icon="⏱️")

with col_meta:
	st.subheader("Info")
	st.caption("- Badges show model intent, language, and sentiment\n- Answers may include KB attribution")

st.markdown("<div class='hr'></div>", unsafe_allow_html=True)

# Render history
for entry in st.session_state.history[-50:]:
	role = entry.get("role")
	text = entry.get("text", "")
	meta = entry.get("meta") or {}
	when = time.strftime("%H:%M:%S", time.localtime(entry.get("ts", time.time())))
	if role == "user":
		st.markdown(f"<div class='bubble user'><b>You</b> · <span class='meta'>{when}</span><br/>{text}</div>", unsafe_allow_html=True)
	else:
		badges = []
		if meta.get("intent"): badges.append(f"<span class='badge'>intent: {meta['intent']}</span>")
		if meta.get("language"): badges.append(f"<span class='badge'>lang: {meta['language']}</span>")
		sent = meta.get("sentiment")
		if sent: badges.append(f"<span class='badge'>sentiment: {sent}</span>")
		source = meta.get("source_id")
		snippet = meta.get("snippet")
		badges_html = " ".join(badges)
		content = f"<div class='bubble bot'><b>Bot</b> · <span class='meta'>{when}</span><br/>{text}<div class='meta'>{badges_html}</div>"
		if source:
			content += f"<div class='meta'>source: {source}</div>"
		if snippet:
			content += f"<div class='meta'>snippet: {snippet}</div>"
		content += "</div>"
		st.markdown(content, unsafe_allow_html=True)

# Suggested follow-ups
if st.session_state.history:
	last = st.session_state.history[-1]
	if last.get("role") == "bot":
		fups = (last.get("meta") or {}).get("suggested_followups") or []
		if fups:
			st.subheader("Suggested follow-ups")
			cols = st.columns(len(fups))
			for i, s in enumerate(fups):
				if cols[i].button(s):
					with st.spinner("Thinking..."):
						resp = api_chat(s)
						st.session_state.history.append({"role":"user","text":s,"ts":time.time()})
						st.session_state.history.append({"role":"bot","text":resp.get("answer","(no answer)"),"ts":time.time(),"meta":resp})
						st.rerun()