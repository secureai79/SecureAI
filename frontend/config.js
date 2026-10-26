/* Where the SecureAI API lives. Empty = same origin as this page (or http://127.0.0.1:8001 when developing locally).
   For a split deployment (static host + separate API) set it at build time: python scripts/build_frontend.py --api https://api.example.com */
window.SECUREAI_API_BASE = "python scripts/build_frontend.py --api https://secureai-za8b.onrender.com";
