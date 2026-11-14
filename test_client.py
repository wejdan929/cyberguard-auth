import time
import requests

# L'adresse de ton API FastAPI en local
BASE_URL = "http://127.0.0.1:8000"

print("=== ÉTAPE 1 : Test de la route de prédiction (/predict) ===")

# Un cas de trafic ambigu ou suspect à tester
payload_test = {
    "failed_logins": 5,
    "request_frequency": 15.0,
    "payload_size": 2500,
    "ip_reputation": 0.84,
}

# Envoi de la requête POST vers /predict
response_predict = requests.post(f"{BASE_URL}/predict", json=payload_test)
result_predict = response_predict.json()

print(f"Données envoyées : {payload_test}")
print(f"Réponse du modèle : {result_predict}")

# Petite pause pour bien voir l'enchaînement dans la console
time.sleep(2)

print(
    "\n=== ÉTAPE 2 : Simulation d'un faux positif et envoi du feedback (/feedback)"
    " ==="
)
print(
    "Imaginons que ce trafic était en réalité LÉGITIME (faux positif du"
    " modèle)."
)

# Construction du feedback correctif basé sur les mêmes données
feedback_data = {
    "failed_logins": payload_test["failed_logins"],
    "request_frequency": payload_test["request_frequency"],
    "payload_size": payload_test["payload_size"],
    "ip_reputation": payload_test["ip_reputation"],
    "actual_status": 0,  # 0 signifie : "C'était du trafic légitime, ne le bloque pas !"
    "comment": "Correction automatique d'un faux positif par le client de test.",
}

# Envoi de la requête POST vers /feedback
response_feedback = requests.post(f"{BASE_URL}/feedback", json=feedback_data)
result_feedback = response_feedback.json()

print(f"Réponse de la boucle fermée : {result_feedback}")
print(
    "\n-> Regarde : le seuil adaptatif a automatiquement évolué pour s'ajuster"
    " !"
)