from fastapi import FastAPI

app = FastAPI(title="SoftPOS Test API", version="1.0.0")


@app.get("/health")
async def health():
    return {"status": "healthy", "message": "Test API is running"}


@app.get("/")
async def root():
    return {"message": "SoftPOS Test API", "status": "live"}