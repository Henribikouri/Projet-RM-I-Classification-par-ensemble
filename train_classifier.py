import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler # Exemple pour la normalisation
import joblib
import os

# --- 1. Chargement des données ---
# Assurez-vous que network_traffic_dataset.csv est dans le même répertoire ou spécifiez le chemin complet
data_path = 'network_traffic_dataset.csv' # Le chemin vers votre dataset CSV
if not os.path.exists(data_path):
    print(f"Erreur: Le fichier {data_path} n'a pas été trouvé. Assurez-vous d'avoir exécuté l'extraction de caractéristiques.")
    exit()

df = pd.read_csv(data_path)
print(f"Dataset chargé avec {df.shape[0]} lignes et {df.shape[1]} colonnes.")
print("Premières lignes du dataset:")
print(df.head())
print("\nDistribution des classes:")
print(df['label'].value_counts())

# --- 2. Séparation des caractéristiques (X) et des étiquettes (y) ---
X = df.drop('label', axis=1) # Toutes les colonnes sauf 'label'
y = df['label']             # La colonne 'label' (votre classe de trafic)

# Gérer les colonnes non numériques qui pourraient être restées si l'extraction n'était pas parfaite
# Convertir les colonnes booléennes ou autres types non numériques en numériques si nécessaire
for col in X.columns:
    if X[col].dtype == 'object': # Si la colonne est de type objet (string)
        X = pd.get_dummies(X, columns=[col], prefix=col, drop_first=True)
    elif X[col].dtype == 'bool': # Si la colonne est booléenne
        X[col] = X[col].astype(int)

# S'assurer qu'il n'y a pas de NaN (valeurs manquantes) après l'extraction/pré-traitement
X = X.fillna(0) # Remplacer les NaN par 0, ou utiliser une autre stratégie (moyenne, médiane)

# --- 3. Normalisation des caractéristiques numériques ---
# Il est souvent bon de normaliser les données avant l'entraînement, surtout pour certains algorithmes
# Gardez à l'esprit que Random Forest est moins sensible à la mise à l'échelle que d'autres,
# mais c'est une bonne pratique. Appliquez StandardScaler uniquement aux colonnes numériques.
numeric_cols = X.select_dtypes(include=['number']).columns
scaler = StandardScaler()
X[numeric_cols] = scaler.fit_transform(X[numeric_cols])
# Sauvegardez le scaler, vous en aurez besoin pour normaliser les données en temps réel dans Ryu
joblib.dump(scaler, 'scaler.pkl')
print("\nDonnées normalisées. Scaler sauvegardé sous 'scaler.pkl'.")


# --- 4. Séparation des données en ensembles d'entraînement et de test ---
# test_size=0.3 signifie 30% des données pour le test, 70% pour l'entraînement
# random_state assure la reproductibilité des résultats
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
print(f"\nDonnées séparées: Entraînement={X_train.shape[0]} échantillons, Test={X_test.shape[0]} échantillons.")


# --- 5. Choix et entraînement du modèle ---
# Nous utilisons Random Forest pour sa robustesse et sa performance
print("\nEntraînement du modèle RandomForestClassifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1) # n_jobs=-1 pour utiliser tous les cœurs
model.fit(X_train, y_train)
print("Modèle entraîné avec succès.")

# --- 6. Évaluation du modèle ---
print("\nÉvaluation du modèle sur l'ensemble de test...")
y_pred = model.predict(X_test)

print(f"Précision (Accuracy) globale: {accuracy_score(y_test, y_pred):.4f}")
print("\nMatrice de Confusion:\n", confusion_matrix(y_test, y_pred))
print("\nRapport de Classification (Precision, Recall, F1-score):\n", classification_report(y_test, y_pred))

# --- 7. Sauvegarde du modèle entraîné ---
model_filename = 'traffic_classifier_model.pkl'
joblib.dump(model, model_filename)
print(f"\nModèle sauvegardé sous '{model_filename}'.")

print("\nScript d'entraînement terminé.")