
"""
Nettoyeur de fichiers vides + Antivirus par signature (VirusTotal)
Application de bureau Tkinter
-------------------------------------------------------------------
Fonctionnalités :
1. Scanner un dossier et lister/supprimer les fichiers vides (0 octet)
2. Calculer le hash SHA-256 de chaque fichier et interroger la base
   de VirusTotal (via leur API officielle v3) pour voir si le fichier
   est connu comme malveillant.

Prérequis :
    pip install requests

Clé API VirusTotal :
    Créez un compte gratuit sur https://www.virustotal.com
    Récupérez votre clé API dans "Profil > API Key"
    Collez-la dans le champ prévu dans l'application (elle n'est
    jamais envoyée ailleurs qu'à l'API officielle de VirusTotal).

Limites du compte gratuit VirusTotal : ~4 requêtes/minute.
"""

import os
import hashlib
import threading
import queue
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import requests
except ImportError:
    requests = None

VT_API_URL = "https://www.virustotal.com/api/v3/files/{}"




def calculer_sha256(chemin_fichier, taille_bloc=65536):
    """Calcule le hash SHA-256 d'un fichier."""
    sha256 = hashlib.sha256()
    try:
        with open(chemin_fichier, "rb") as f:
            for bloc in iter(lambda: f.read(taille_bloc), b""):
                sha256.update(bloc)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def lister_fichiers(dossier):
    """Retourne la liste de tous les fichiers dans un dossier (récursif)."""
    fichiers = []
    for racine, _dirs, noms in os.walk(dossier):
        for nom in noms:
            fichiers.append(os.path.join(racine, nom))
    return fichiers


def interroger_virustotal(hash_sha256, api_key):
    """
    Interroge la base de données VirusTotal pour un hash donné.
    Retourne un dict avec le résultat, ou None en cas d'erreur/inconnu.
    """
    if requests is None:
        return {"erreur": "Le module 'requests' n'est pas installé."}

    headers = {"x-apikey": api_key}
    try:
        reponse = requests.get(
            VT_API_URL.format(hash_sha256), headers=headers, timeout=15
        )
    except requests.RequestException as e:
        return {"erreur": f"Erreur réseau : {e}"}

    if reponse.status_code == 200:
        data = reponse.json()
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        nom_vt = (
            data.get("data", {})
            .get("attributes", {})
            .get("meaningful_name", "")
        )
        return {
            "connu": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "nom_vt": nom_vt,
        }
    elif reponse.status_code == 404:
        return {"connu": False}
    elif reponse.status_code == 401:
        return {"erreur": "Clé API invalide ou manquante."}
    elif reponse.status_code == 429:
        return {"erreur": "Limite de requêtes VirusTotal atteinte (quota). Patientez."}
    else:
        return {"erreur": f"Erreur VirusTotal (code {reponse.status_code})."}




class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Nettoyeur de fichiers vides + Antivirus VirusTotal")
        self.geometry("880x620")
        self.minsize(760, 520)

        self.dossier_selectionne = tk.StringVar()
        self.api_key = tk.StringVar()
        self.fichiers_vides = []
        self.file_scan_queue = queue.Queue()

        self._construire_interface()


    def _construire_interface(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.onglet_nettoyage = ttk.Frame(notebook)
        self.onglet_antivirus = ttk.Frame(notebook)

        notebook.add(self.onglet_nettoyage, text="🧹 Nettoyeur de fichiers vides")
        notebook.add(self.onglet_antivirus, text="🛡️ Antivirus (VirusTotal)")

        self._construire_onglet_nettoyage()
        self._construire_onglet_antivirus()


    def _construire_onglet_nettoyage(self):
        frame = self.onglet_nettoyage

        top = ttk.Frame(frame)
        top.pack(fill="x", pady=8, padx=8)

        ttk.Label(top, text="Dossier à analyser :").pack(side="left")
        entry = ttk.Entry(top, textvariable=self.dossier_selectionne, width=60)
        entry.pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(top, text="Parcourir...", command=self.choisir_dossier).pack(side="left")

        style = ttk.Style()
        style.configure("Action.TButton", font=("TkDefaultFont", 10, "bold"))

        btns = ttk.Frame(frame)
        btns.pack(fill="x", padx=8, pady=4)
        ttk.Button(
            btns, text="🔍 Chercher", style="Action.TButton",
            command=self.scanner_fichiers_vides,
        ).pack(side="left")
        ttk.Button(
            btns, text="🧹 Nettoyer", style="Action.TButton",
            command=self.nettoyer_tout,
        ).pack(side="left", padx=6)
        ttk.Button(btns, text="🗑️ Supprimer la sélection", command=self.supprimer_fichiers_vides).pack(side="left", padx=6)
        ttk.Button(btns, text="Tout sélectionner", command=self.tout_selectionner_vides).pack(side="left", padx=6)
        ttk.Button(btns, text="📄 Exporter la liste", command=self.exporter_fichiers_vides).pack(side="left", padx=6)

        # Liste des fichiers vides avec cases à cocher (via Treeview + colonne état)
        self.liste_vides = ttk.Treeview(
            frame, columns=("chemin", "taille"), show="headings", selectmode="extended"
        )
        self.liste_vides.heading("chemin", text="Chemin du fichier")
        self.liste_vides.heading("taille", text="Taille")
        self.liste_vides.column("chemin", width=650)
        self.liste_vides.column("taille", width=100, anchor="center")
        self.liste_vides.pack(fill="both", expand=True, padx=8, pady=8)

        self.label_statut_nettoyage = ttk.Label(frame, text="Prêt.")
        self.label_statut_nettoyage.pack(fill="x", padx=8, pady=(0, 8))

    def choisir_dossier(self):
        dossier = filedialog.askdirectory()
        if dossier:
            self.dossier_selectionne.set(dossier)

    def scanner_fichiers_vides(self):
        dossier = self.dossier_selectionne.get().strip()
        if not dossier or not os.path.isdir(dossier):
            messagebox.showwarning("Attention", "Veuillez choisir un dossier valide.")
            return

        self.liste_vides.delete(*self.liste_vides.get_children())
        self.fichiers_vides = []

        fichiers = lister_fichiers(dossier)
        for chemin in fichiers:
            try:
                taille = os.path.getsize(chemin)
            except OSError:
                continue
            if taille == 0:
                self.fichiers_vides.append(chemin)
                self.liste_vides.insert("", "end", values=(chemin, "0 octet"))

        self.label_statut_nettoyage.config(
            text=f"{len(self.fichiers_vides)} fichier(s) vide(s) trouvé(s) sur {len(fichiers)} analysé(s)."
        )

    def tout_selectionner_vides(self):
        self.liste_vides.selection_set(self.liste_vides.get_children())

    def exporter_fichiers_vides(self):
        """Écrit les chemins des fichiers vides listés dans un fichier texte."""
        items = self.liste_vides.get_children()
        if not items:
            messagebox.showinfo("Info", "Aucun fichier vide à exporter. Lancez d'abord « 🔍 Chercher ».")
            return

        chemin_export = filedialog.asksaveasfilename(
            title="Enregistrer la liste des fichiers vides",
            defaultextension=".txt",
            initialfile="fichiers_vides.txt",
            filetypes=[("Fichier texte", "*.txt"), ("Tous les fichiers", "*.*")],
        )
        if not chemin_export:
            return

        try:
            with open(chemin_export, "w", encoding="utf-8") as f:
                for item in items:
                    chemin = self.liste_vides.item(item, "values")[0]
                    f.write(chemin + "\n")
            messagebox.showinfo("Terminé", f"{len(items)} chemin(s) exporté(s) vers :\n{chemin_export}")
        except OSError as e:
            messagebox.showerror("Erreur", f"Impossible d'écrire le fichier : {e}")

    def nettoyer_tout(self):
        """Cherche les fichiers vides et les supprime directement, en un seul clic."""
        dossier = self.dossier_selectionne.get().strip()
        if not dossier or not os.path.isdir(dossier):
            messagebox.showwarning("Attention", "Veuillez choisir un dossier valide.")
            return

        fichiers = lister_fichiers(dossier)
        a_supprimer = []
        for chemin in fichiers:
            try:
                if os.path.getsize(chemin) == 0:
                    a_supprimer.append(chemin)
            except OSError:
                continue

        if not a_supprimer:
            messagebox.showinfo("Info", "Aucun fichier vide trouvé. Rien à nettoyer.")
            self.label_statut_nettoyage.config(text="Aucun fichier vide trouvé.")
            return

        confirmation = messagebox.askyesno(
            "Confirmation",
            f"{len(a_supprimer)} fichier(s) vide(s) trouvé(s). Les supprimer définitivement maintenant ?",
        )
        if not confirmation:
            return

        supprimes = 0
        erreurs = []
        for chemin in a_supprimer:
            try:
                os.remove(chemin)
                supprimes += 1
            except OSError as e:
                erreurs.append(f"{chemin} : {e}")

        # Rafraîchir la liste affichée
        self.scanner_fichiers_vides()

        message = f"Nettoyage terminé : {supprimes} fichier(s) supprimé(s)."
        if erreurs:
            message += f"\n\nErreurs :\n" + "\n".join(erreurs[:10])
        messagebox.showinfo("Terminé", message)
        self.label_statut_nettoyage.config(text=message.splitlines()[0])

    def supprimer_fichiers_vides(self):
        selection = self.liste_vides.selection()
        if not selection:
            messagebox.showinfo("Info", "Aucun fichier sélectionné.")
            return

        chemins = [self.liste_vides.item(item, "values")[0] for item in selection]
        confirmation = messagebox.askyesno(
            "Confirmation",
            f"Supprimer définitivement {len(chemins)} fichier(s) vide(s) ?",
        )
        if not confirmation:
            return

        supprimes = 0
        erreurs = []
        for chemin in chemins:
            try:
                os.remove(chemin)
                supprimes += 1
            except OSError as e:
                erreurs.append(f"{chemin} : {e}")

        for item in selection:
            self.liste_vides.delete(item)

        message = f"{supprimes} fichier(s) supprimé(s)."
        if erreurs:
            message += f"\n\nErreurs :\n" + "\n".join(erreurs[:10])
        messagebox.showinfo("Terminé", message)
        self.label_statut_nettoyage.config(text=message.splitlines()[0])

  
    def _construire_onglet_antivirus(self):
        frame = self.onglet_antivirus

        top = ttk.Frame(frame)
        top.pack(fill="x", padx=8, pady=8)

        ttk.Label(top, text="Clé API VirusTotal :").pack(side="left")
        entry_api = ttk.Entry(top, textvariable=self.api_key, width=40, show="*")
        entry_api.pack(side="left", padx=6)
        ttk.Label(
            top,
            text="(gratuite sur virustotal.com > Profil > API Key)",
            foreground="gray",
        ).pack(side="left")

        dossier_frame = ttk.Frame(frame)
        dossier_frame.pack(fill="x", padx=8, pady=4)
        ttk.Label(dossier_frame, text="Dossier à scanner :").pack(side="left")
        entry = ttk.Entry(dossier_frame, textvariable=self.dossier_selectionne, width=55)
        entry.pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(dossier_frame, text="Parcourir...", command=self.choisir_dossier).pack(side="left")

        btns = ttk.Frame(frame)
        btns.pack(fill="x", padx=8, pady=4)
        self.btn_scan_av = ttk.Button(
            btns, text="🔍 Chercher", style="Action.TButton",
            command=self.lancer_scan_antivirus,
        )
        self.btn_scan_av.pack(side="left")
        ttk.Button(
            btns, text="🧹 Nettoyer (supprimer les fichiers malveillants)",
            style="Action.TButton", command=self.nettoyer_fichiers_malveillants,
        ).pack(side="left", padx=6)
        ttk.Button(btns, text="Chercher un seul fichier...", command=self.analyser_un_fichier).pack(side="left", padx=6)
        ttk.Button(btns, text="📄 Exporter les résultats", command=self.exporter_resultats_antivirus).pack(side="left", padx=6)

        self.progress = ttk.Progressbar(frame, mode="determinate")
        self.progress.pack(fill="x", padx=8, pady=(4, 0))

        self.liste_resultats = ttk.Treeview(
            frame,
            columns=("fichier", "resultat", "detections"),
            show="headings",
        )
        self.liste_resultats.heading("fichier", text="Fichier")
        self.liste_resultats.heading("resultat", text="Résultat")
        self.liste_resultats.heading("detections", text="Détections")
        self.liste_resultats.column("fichier", width=430)
        self.liste_resultats.column("resultat", width=180, anchor="center")
        self.liste_resultats.column("detections", width=150, anchor="center")
        self.liste_resultats.pack(fill="both", expand=True, padx=8, pady=8)

        # Couleurs pour les tags
        self.liste_resultats.tag_configure("danger", foreground="white", background="#c0392b")
        self.liste_resultats.tag_configure("suspect", foreground="black", background="#f39c12")
        self.liste_resultats.tag_configure("propre", foreground="black", background="#d5f5e3")
        self.liste_resultats.tag_configure("inconnu", foreground="black", background="#ecf0f1")
        self.liste_resultats.tag_configure("erreur", foreground="white", background="#7f8c8d")

        self.label_statut_av = ttk.Label(frame, text="Prêt.")
        self.label_statut_av.pack(fill="x", padx=8, pady=(0, 8))

        if requests is None:
            messagebox.showwarning(
                "Module manquant",
                "Le module Python 'requests' n'est pas installé.\n"
                "Installez-le avec : pip install requests",
            )

    def analyser_un_fichier(self):
        chemin = filedialog.askopenfilename()
        if not chemin:
            return
        api_key = self.api_key.get().strip()
        if not api_key:
            messagebox.showwarning("Attention", "Veuillez saisir votre clé API VirusTotal.")
            return
        threading.Thread(
            target=self._analyser_fichiers_thread, args=([chemin], api_key), daemon=True
        ).start()

    def lancer_scan_antivirus(self):
        dossier = self.dossier_selectionne.get().strip()
        api_key = self.api_key.get().strip()

        if not dossier or not os.path.isdir(dossier):
            messagebox.showwarning("Attention", "Veuillez choisir un dossier valide.")
            return
        if not api_key:
            messagebox.showwarning("Attention", "Veuillez saisir votre clé API VirusTotal.")
            return
        if requests is None:
            messagebox.showerror("Erreur", "Le module 'requests' n'est pas installé.")
            return

        fichiers = lister_fichiers(dossier)
        if not fichiers:
            messagebox.showinfo("Info", "Aucun fichier trouvé dans ce dossier.")
            return

        confirmation = messagebox.askyesno(
            "Confirmation",
            f"{len(fichiers)} fichier(s) trouvé(s). L'analyse peut être lente "
            f"(quota gratuit VirusTotal ≈ 4 requêtes/minute). Continuer ?",
        )
        if not confirmation:
            return

        self.liste_resultats.delete(*self.liste_resultats.get_children())
        self.btn_scan_av.config(state="disabled")
        threading.Thread(
            target=self._analyser_fichiers_thread, args=(fichiers, api_key), daemon=True
        ).start()

    def _analyser_fichiers_thread(self, fichiers, api_key):
        total = len(fichiers)
        self.progress.config(maximum=total, value=0)

        for i, chemin in enumerate(fichiers, start=1):
            self.label_statut_av.config(text=f"Analyse en cours : {os.path.basename(chemin)} ({i}/{total})")
            self.progress.config(value=i)

            hash_sha256 = calculer_sha256(chemin)
            if hash_sha256 is None:
                self._ajouter_resultat(chemin, "Illisible", "-", "erreur")
                continue

            resultat = interroger_virustotal(hash_sha256, api_key)

            if "erreur" in resultat:
                self._ajouter_resultat(chemin, resultat["erreur"], "-", "erreur")
                if "quota" in resultat["erreur"].lower() or "Limite" in resultat["erreur"]:
                    time.sleep(20)  # pause si quota atteint
                continue

            if not resultat.get("connu"):
                self._ajouter_resultat(chemin, "Inconnu de VirusTotal", "-", "inconnu")
            else:
                malicious = resultat["malicious"]
                suspicious = resultat["suspicious"]
                if malicious > 0:
                    self._ajouter_resultat(
                        chemin, "⚠️ MALVEILLANT", f"{malicious} moteur(s)", "danger"
                    )
                elif suspicious > 0:
                    self._ajouter_resultat(
                        chemin, "Suspect", f"{suspicious} moteur(s)", "suspect"
                    )
                else:
                    self._ajouter_resultat(chemin, "Propre", "0 détection", "propre")

            # Respect du quota gratuit VirusTotal (~4 req/min => 1 toutes les 15s)
            time.sleep(16)

        self.label_statut_av.config(text=f"Analyse terminée. {total} fichier(s) traité(s).")
        self.btn_scan_av.config(state="normal")

    def exporter_resultats_antivirus(self):
        """Écrit les chemins + résultats de l'analyse antivirus dans un fichier texte."""
        items = self.liste_resultats.get_children()
        if not items:
            messagebox.showinfo("Info", "Aucun résultat à exporter. Lancez d'abord « 🔍 Chercher ».")
            return

        chemin_export = filedialog.asksaveasfilename(
            title="Enregistrer les résultats antivirus",
            defaultextension=".txt",
            initialfile="resultats_antivirus.txt",
            filetypes=[("Fichier texte", "*.txt"), ("CSV", "*.csv"), ("Tous les fichiers", "*.*")],
        )
        if not chemin_export:
            return

        try:
            with open(chemin_export, "w", encoding="utf-8") as f:
                f.write("Fichier\tResultat\tDetections\n")
                for item in items:
                    chemin, resultat, detections = self.liste_resultats.item(item, "values")
                    f.write(f"{chemin}\t{resultat}\t{detections}\n")
            messagebox.showinfo("Terminé", f"{len(items)} résultat(s) exporté(s) vers :\n{chemin_export}")
        except OSError as e:
            messagebox.showerror("Erreur", f"Impossible d'écrire le fichier : {e}")

    def nettoyer_fichiers_malveillants(self):
        """Supprime du disque tous les fichiers marqués MALVEILLANT dans les résultats."""
        items_dangereux = [
            item for item in self.liste_resultats.get_children()
            if "danger" in self.liste_resultats.item(item, "tags")
        ]

        if not items_dangereux:
            messagebox.showinfo(
                "Info",
                "Aucun fichier malveillant dans les résultats actuels.\n"
                "Lancez d'abord une recherche avec le bouton « 🔍 Chercher ».",
            )
            return

        chemins = [self.liste_resultats.item(item, "values")[0] for item in items_dangereux]
        confirmation = messagebox.askyesno(
            "Confirmation",
            f"⚠️ {len(chemins)} fichier(s) détecté(s) comme MALVEILLANT(S) :\n\n"
            + "\n".join(chemins[:10])
            + ("\n..." if len(chemins) > 10 else "")
            + "\n\nLes supprimer définitivement du disque ?",
        )
        if not confirmation:
            return

        supprimes = 0
        erreurs = []
        for chemin in chemins:
            try:
                os.remove(chemin)
                supprimes += 1
            except OSError as e:
                erreurs.append(f"{chemin} : {e}")

        for item in items_dangereux:
            self.liste_resultats.delete(item)

        message = f"Nettoyage terminé : {supprimes} fichier(s) malveillant(s) supprimé(s)."
        if erreurs:
            message += "\n\nErreurs :\n" + "\n".join(erreurs[:10])
        messagebox.showinfo("Terminé", message)
        self.label_statut_av.config(text=message.splitlines()[0])

    def _ajouter_resultat(self, chemin, resultat, detections, tag):
        self.after(0, lambda: self.liste_resultats.insert(
            "", "end", values=(chemin, resultat, detections), tags=(tag,)
        ))


# ----------------------------------------------------------------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
