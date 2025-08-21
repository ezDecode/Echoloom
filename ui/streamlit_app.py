import os
import streamlit as st
from client import chat as api_chat

st.set_page_config(page_title="Echoloom Chat", page_icon="💬", layout="centered")

# Inject Google Font and dark theme CSS
st.markdown(
	"""
	<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,200..800;1,200..800&display=swap" rel="stylesheet">
	<style>
	:root {
		--fg: #ffffff;
		--bg: #000000;
		--bg-secondary: #111111;
		--accent: #6EE7F9;
	}
	html, body, [data-testid="stAppViewContainer"] {
		background-color: var(--bg) !important;
		color: var(--fg) !important;
		font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important;
	}
	[data-testid="stSidebar"] {
		background-color: var(--bg-secondary) !important;
	}
	.stTextInput input, .stTextArea textarea {
		background-color: #0e0e0e !important;
		color: var(--fg) !important;
		border: 1px solid #222 !important;
	}
	.stButton button {
		background: linear-gradient(90deg, #111, #333) !important;
		color: var(--fg) !important;
		border: 1px solid #333 !important;
	}
	</style>
	""",
	unsafe_allow_html=True,
)

st.title("Echoloom Chat 💬")
api_url = os.getenv("API_URL", "http://localhost:8000")
api_key = os.getenv("API_KEY", "dev-key-123")
st.caption(f"Backend: {api_url}")

if "history" not in st.session_state:
	st.session_state.history = []

with st.form("chat-form"):
	msg = st.text_input("Your message", key="msg", placeholder="Type a message...")
	send = st.form_submit_button("Send")

if send and msg.strip():
	try:
		resp = api_chat(msg)
		st.session_state.history.append(("user", msg))
		answer = resp.get("answer", "(no answer)")
		st.session_state.history.append(("bot", answer))
	except Exception as e:
		st.error(f"Error: {e}")

for role, text in st.session_state.history[-20:]:
	if role == "user":
		st.markdown(f"**You:** {text}")
	else:
		st.markdown(f"**Bot:** {text}")