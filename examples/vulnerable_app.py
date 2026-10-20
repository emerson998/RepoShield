"""Synthetic fixture for RepoShield. Never deploy this example."""
from fastapi import FastAPI
app=FastAPI(debug=True)
@app.get('/health')
def health():
    return {'status':'ok'}
@app.get('/orders/{order_id}')
def order(order_id: str):
    return {'order':order_id}
@app.delete('/admin/users/{user_id}')
def remove_user(user_id: str):
    return {'deleted':user_id}
