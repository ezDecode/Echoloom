from echoloom.app import create_app
import json

if __name__ == "__main__":
	app = create_app()
	with open("openapi.json", "w", encoding="utf-8") as f:
		json.dump(app.openapi(), f, indent=2)
	print("openapi.json written")