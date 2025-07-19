from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer
from routes.router import router as auth_router

app = FastAPI(
    title="FARM Stack API",
    description="API for FARM Stack Application",
    version="1.0.0"
)

# Configure OAuth2 for Swagger UI
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app.include_router(auth_router)
