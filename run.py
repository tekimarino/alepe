from app.app import create_app
import os

app = create_app()

if __name__ == "__main__":
    # Dev server (port configurable via env PORT)
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="127.0.0.1", port=port, debug=True)
