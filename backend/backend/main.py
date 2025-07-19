from fastapi import FastAPI
from routes.router import router as auth_router

app = FastAPI()

app.include_router(auth_router)
