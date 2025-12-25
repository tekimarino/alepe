# Élections Alépé — Site des résultats (Flask + JSON)

Ce dépôt contient **2 applications** :
- **Résultats** (celle que tu veux pour Alépé) → démarre avec `run.py` (port **5001** par défaut)
- **Recensement** (si tu l’utilises) → démarre avec `app.py` (port **5001** par défaut)

## Démarrage rapide (Résultats — Alépé)
### Windows
1. Double-clique sur `run_windows.bat`  
   (ou `run_windows.bat 5002` pour changer le port)
2. Ouvre : http://127.0.0.1:5001

### macOS / Linux
```bash
chmod +x run_linux_mac.sh
./run_linux_mac.sh
# ou: ./run_linux_mac.sh 5002
```
Puis ouvre : http://127.0.0.1:5001

### Identifiants admin (Résultats)
- **Username** : `admin`
- **Mot de passe** : `AdminAlepe2025!`

> Les données de résultats sont **vides** au départ (Alépé). Tu pourras importer/ajouter centres, bureaux, candidats, etc.

---

# Recensement Électoral 2028 (Flask + JSON, sans base de données)

Application légère pour enregistrer des électeurs (via des agents recenseurs) et valider les données (via des superviseurs par zone).

## Fonctionnalités
- Comptes utilisateurs avec rôles : **admin**, **supervisor**, **agent**
- Gestion des **zones** (admin)
- Création de **superviseurs** (assignés à une zone) et d’**agents** (assignés à une zone + un superviseur)
- Saisie côté agent : **Nom, Prénoms, Date de naissance, Quartier, Téléphone**
- Validation côté superviseur : ajout du **Numéro d’électeur**, **Centre de vote** et **Bureau de vote** + statut (**Validé / Rejeté**)
- Stockage **100% fichier** (JSON) : `data/users.json`, `data/zones.json`, `data/registrations.json`
- Admin : accès à la **liste des personnes recensées** avec recherche + filtres (zone, centre de vote)
- **SMS de masse** (admin) et **SMS de zone** (superviseur) via une file d’attente JSON : `data/sms_outbox.json` + campagnes `data/sms_campaigns.json`

## Comptes par défaut (à changer immédiatement)
- Admin : `admin` / `Admin2028@`
- Superviseur : `sup_adiaho` / `Sup2028@`
- Agent : `agent_01` / `Agent2028@`

> Important : modifiez ces mots de passe dès le démarrage (menu Admin > Utilisateurs).

## Installation (local)
1. Installer Python 3.10+.
2. Ouvrir un terminal dans le dossier du projet, puis :
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS/Linux:
   source .venv/bin/activate

   pip install -r requirements.txt
   ```
3. Lancer :
   ```bash
   python app.py
   ```
4. Ouvrir : http://127.0.0.1:5000

## Sécurité (minimum vital)
- Changez la clé de session Flask :
  - Créez une variable d’environnement `SECRET_KEY` (forte et privée)
- En production, exécutez derrière un reverse proxy HTTPS (Nginx, Caddy, etc.)
- Sauvegardez régulièrement le dossier `data/` (il contient toutes les informations).

## Déploiement simple (exemple)
- Utilisez un VPS (DigitalOcean, OVH, etc.)
- Installez Python + dépendances
- Lancez avec un serveur WSGI (ex. gunicorn) derrière Nginx, avec HTTPS

## Structure
- `app.py` : application Flask
- `templates/` : pages HTML
- `static/` : CSS/JS
- `data/` : fichiers JSON (données)


## SMS (mode simulation par défaut)
Par défaut, l’application est en **mode DRY_RUN** : les SMS sont ajoutés à une file (`data/sms_outbox.json`) mais **aucun fournisseur n’est contacté**.

Pour brancher un fournisseur via une API HTTP JSON :
1. Ouvrez `data/sms_config.json`
2. Mettez `"mode": "http_json"`
3. Renseignez `http_json.url` (endpoint) et, si besoin, `http_json.token` (Bearer)
4. Cliquez sur **Traiter la file** (envois par lots, max `MAX_SMS_SEND_PER_REQUEST` par clic)

> Note : chaque fournisseur a son format. Ici, on envoie un JSON simple `{to, message, sender}` (configurable via `to_field`, `message_field`, `sender_field`).
