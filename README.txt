Correctif: afficher le Centre + Bureau dans la liste "Bureau affecté" (représentant)

Fichiers concernés (à remplacer dans votre projet):
1) elections/app/templates/admin_users.html
2) elections/app/templates/admin_user_edit.html
3) elections/app/app.py

Option A (simple): remplacez les 3 fichiers par ceux fournis ici.

Option B (propre via Git): appliquez le patch:
git apply correctif_affectation_centre_dropdown.patch

Puis relancez l'application.
