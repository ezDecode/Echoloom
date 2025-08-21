import os
import streamlit as st
from client import chat as api_chat

st.set_page_config(page_title="Echoloom Chat", page_icon="💬", layout="centered")

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