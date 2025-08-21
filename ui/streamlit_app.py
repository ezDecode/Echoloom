import os
import sys
import time
import streamlit as st

# Robust import for client helper whether run as a module or script
try:
	from .client import chat as api_chat, set_api_config
except Exception:
	sys.path.append(os.path.dirname(os.path.abspath(__file__)))
	from client import chat as api_chat, set_api_config  # type: ignore

st.set_page_config(page_title="Echoloom Chat", page_icon="💬", layout="wide")

# Inject Google Font and dark theme CSS
st.markdown(
	"""
	<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,200..800;1,200..800&display=swap" rel="stylesheet">
	<style>
	:root { --fg:#ffffff; --bg:#000000; --bg2:#0e0e0e; --accent:#6EE7F9; --muted:#9CA3AF; }
	html, body, [data-testid="stAppViewContainer"] { background-color: var(--bg)!important; color: var(--fg)!important; font-family: 'Plus Jakarta Sans', system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif!important; }
	.badge { display:inline-block; padding:4px 8px; border-radius:9999px; background:#1f2937; border:1px solid #374151; color:#e5e7eb; font-size:12px; margin-right:6px; }
	.msg { display:flex; gap:10px; align-items:flex-start; margin:10px 0; }
	.avatar { width:32px; height:32px; display:flex; align-items:center; justify-content:center; border-radius:9999px; background:#111827; border:1px solid #1f2937; }
	.bubble { border-radius:16px; padding:12px 14px; max-width: 900px; background:#0b1320; border:1px solid #1f2937; }
	.user .bubble { background:#111827; }
	.meta { color: var(--muted); font-size:12px; margin-top:6px; }
	.hr { height:1px; background:#1f2937; margin:12px 0; }
	.stChatInput input, .stTextInput input { background-color: var(--bg2)!important; color: var(--fg)!important; border:1px solid #222!important; }
	.stButton button { background: linear-gradient(90deg, #111, #333)!important; color: var(--fg)!important; border:1px solid #333!important; }
	</style>
	""",
	unsafe_allow_html=True,
)

# Sidebar configuration with persistence
with st.sidebar:
	st.header("Settings")
	if "api_url" not in st.session_state:
		st.session_state.api_url = os.getenv("API_URL", "http://localhost:8000")
	if "api_key" not in st.session_state:
		st.session_state.api_key = os.getenv("API_KEY", "dev-key-123")
	api_url = st.text_input("API URL", st.session_state.api_url)
	api_key = st.text_input("API Key", st.session_state.api_key)
	apply = st.button("Apply")
	if apply:
		st.session_state.api_url = api_url
		st.session_state.api_key = api_key
		set_api_config(api_url, api_key)
		st.success("Applied API settings")
	st.markdown("---")
	if st.button("Clear chat"):
		st.session_state.history = []
		st.rerun()

st.title("Echoloom Chat 💬")

# Conversation state
if "history" not in st.session_state:
	st.session_state.history = []

# Messages container
messages = st.container()

# Render history
with messages:
	for entry in st.session_state.history[-100:]:
		role = entry.get("role")
		text = entry.get("text", "")
		meta = entry.get("meta") or {}
		when = time.strftime("%H:%M:%S", time.localtime(entry.get("ts", time.time())))
		badges = []
		if meta.get("intent"): badges.append(f"<span class='badge'>intent: {meta['intent']}</span>")
		if meta.get("language"): badges.append(f"<span class='badge'>lang: {meta['language']}</span>")
		sent = meta.get("sentiment")
		if sent: badges.append(f"<span class='badge'>sentiment: {sent}</span>")
		badges_html = " ".join(badges)
		if role == "user":
			st.markdown(f"<div class='msg user'><div class='avatar'>🧑</div><div class='bubble'><b>You</b> · <span class='meta'>{when}</span><div>{text}</div></div></div>", unsafe_allow_html=True)
		else:
			source = meta.get("source_id")
			snippet = meta.get("snippet")
			content = f"<div class='msg bot'><div class='avatar'>🤖</div><div class='bubble'><b>Bot</b> · <span class='meta'>{when}</span><div>{text}</div><div class='meta'>{badges_html}</div>"
			if source:
				content += f"<div class='meta'>source: {source}</div>"
			if snippet:
				content += f"<div class='meta'>snippet: {snippet}</div>"
			content += "</div></div>"
			st.markdown(content, unsafe_allow_html=True)

st.markdown("<div class='hr'></div>", unsafe_allow_html=True)

# Chat input at bottom
prompt = st.chat_input("Type a message...")
if prompt:
	with st.spinner("Thinking..."):
		start = time.time()
		try:
			resp = api_chat(prompt)
			elapsed = time.time() - start
			st.session_state.history.append({"role":"user","text":prompt,"ts":time.time()})
			st.session_state.history.append({"role":"bot","text":resp.get("answer","(no answer)"),"ts":time.time(),"meta":resp})
			st.toast(f"Response in {elapsed:.2f}s", icon="⏱️")
			st.rerun()
		except Exception as e:
			st.error(f"Error: {e}")

# Suggested follow-ups for last bot message
if st.session_state.history:
	last = st.session_state.history[-1]
	if last.get("role") == "bot":
		fups = (last.get("meta") or {}).get("suggested_followups") or []
		if fups:
			st.subheader("Suggested follow-ups")
			cols = st.columns(min(4, len(fups)))
			for i, s in enumerate(fups[:4]):
				if cols[i].button(s):
					with st.spinner("Thinking..."):
						resp = api_chat(s)
						st.session_state.history.append({"role":"user","text":s,"ts":time.time()})
						st.session_state.history.append({"role":"bot","text":resp.get("answer","(no answer)"),"ts":time.time(),"meta":resp})
						st.rerun()