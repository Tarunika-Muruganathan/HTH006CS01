with open("backend_api.py", "r") as f:
    content = f.read()

content = content.replace(
    'from src.cert_engine import (\n    get_db_connection,',
    'from src.cert_engine import (\n    get_db_connection,\n    ingest_data_v2,'
)

init_code = """
@app.on_event("startup")
def startup_event():
    if not DB_PATH.exists():
        print("Ingesting data_v2 dataset. This may take a moment...")
        ingest_data_v2()
        print("Ingestion complete!")
"""

content = content.replace(
    'app = FastAPI(title="Insider Threat Backend")',
    'app = FastAPI(title="Insider Threat Backend")\n' + init_code
)

with open("backend_api.py", "w") as f:
    f.write(content)
