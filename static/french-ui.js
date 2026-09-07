(() => {
    "use strict";

    const dictionary = {
        "Background": "Arrière-plan", "Choose background color": "Choisir la couleur de l'arrière-plan",
        "White": "Blanc", "Black": "Noir", "Green": "Vert", "Blue": "Bleu", "Online": "En ligne",
        "Main": "Principal", "Billing": "Facturation", "Purchases": "Achats", "System": "Système",
        "Dashboard": "Tableau de bord", "Sales / Invoices": "Ventes / Factures",
        "Fidelity Clients": "Clients fidélité", "Float": "Fond de caisse", "Takings": "Recettes",
        "Daily Sales": "Ventes quotidiennes", "Daily Takings": "Recettes quotidiennes", "Reports": "Rapports",
        "Subscription Billing": "Facturation de l'abonnement", "Products": "Produits", "Categories": "Catégories",
        "Purchases / Stock In": "Achats / Entrées en stock", "Stock": "Stock", "Daily Purchases": "Achats quotidiens",
        "Physical Stock": "Inventaire physique", "Barcodes": "Codes-barres", "Decode Barcode": "Décoder un code-barres",
        "Account": "Compte", "Users": "Utilisateurs", "Database": "Base de données", "Receipt Settings": "Paramètres des reçus",
        "Email Settings": "Paramètres e-mail", "Audit Logs": "Journal d'audit", "License": "Licence", "Help": "Aide",
        "Logout": "Déconnexion", "Terms": "Conditions", "Privacy": "Confidentialité", "All rights reserved.": "Tous droits réservés.",
        "Mauritius VAT + Stock": "TVA et stock Maurice", "Welcome to Mauritius POS V3": "Bienvenue dans Mauritius POS V3",
        "Manage sales, stock, purchases and daily takings from one secure workspace.": "Gérez les ventes, le stock, les achats et les recettes quotidiennes depuis un espace de travail sécurisé.",
        "Sign in to continue": "Connectez-vous pour continuer", "Username": "Nom d'utilisateur", "Password": "Mot de passe",
        "Login": "Connexion", "Sign in": "Se connecter", "I have read and agree to the": "J'ai lu et j'accepte les",
        "Terms of Use": "Conditions d'utilisation", "Privacy Policy": "Politique de confidentialité", "and": "et",
        "Choose dashboard background": "Choisir l'arrière-plan du tableau de bord", "Dashboard background": "Arrière-plan du tableau de bord",
        "Products, categories, stock entries, barcode tools and purchase history.": "Produits, catégories, entrées en stock, outils de codes-barres et historique des achats.",
        "Sales, receipts, VAT, takings, float, reports and receipt settings.": "Ventes, reçus, TVA, recettes, fond de caisse, rapports et paramètres des reçus.",
        "Products / Suppliers": "Produits / Fournisseurs", "Stock Entry": "Entrée de stock", "Open": "Ouvrir",
        "Add product": "Ajouter un produit", "Edit product": "Modifier le produit", "Product name": "Nom du produit",
        "Product": "Produit", "Products": "Produits", "SKU / Barcode": "SKU / Code-barres", "SKU / Product code": "SKU / Code produit",
        "Brand": "Marque", "Size": "Taille", "Category": "Catégorie", "Categories": "Catégories", "Supplier": "Fournisseur",
        "Cost price": "Prix d'achat", "Selling price": "Prix de vente", "Unit cost (Rs)": "Coût unitaire (Rs)",
        "Quantity": "Quantité", "Qty": "Qté", "Unit": "Unité", "Active": "Actif", "Inactive": "Inactif",
        "Save": "Enregistrer", "Cancel": "Annuler", "Edit": "Modifier", "Delete": "Supprimer", "Remove": "Retirer",
        "Search": "Rechercher", "Filter": "Filtrer", "Apply filter": "Appliquer le filtre", "From": "Du", "To": "Au", "Date": "Date",
        "Product Categories": "Catégories de produits", "Category name": "Nom de la catégorie", "Add category": "Ajouter une catégorie",
        "Create cashier user": "Créer un utilisateur caissier", "Create user": "Créer l'utilisateur", "Full name": "Nom complet",
        "Role": "Rôle", "Admin": "Administrateur", "Cashier": "Caissier", "Update": "Mettre à jour",
        "My account": "Mon compte", "Current password": "Mot de passe actuel", "New password": "Nouveau mot de passe",
        "Confirm new password": "Confirmer le nouveau mot de passe", "Update password": "Mettre à jour le mot de passe",
        "Admin audit logs": "Journal d'audit administrateur", "Action": "Action", "User": "Utilisateur",
        "Scan / Add item to cart": "Scanner / Ajouter un article au panier",
        "Use a USB/Bluetooth barcode reader in keyboard mode and scan into the first field.": "Utilisez un lecteur de codes-barres USB/Bluetooth en mode clavier et scannez dans le premier champ.",
        "Scan barcode / type SKU": "Scanner le code-barres / saisir le SKU", "Sale date": "Date de vente",
        "Select product": "Sélectionner un produit", "Select product manually (optional)": "Sélectionner un produit manuellement (facultatif)",
        "Add to cart": "Ajouter au panier", "Add to Cart": "Ajouter au panier", "Current cart": "Panier actuel",
        "Cart": "Panier", "Cart is empty.": "Le panier est vide.", "Line total": "Total de la ligne",
        "Cart subtotal:": "Sous-total du panier :", "Cart VAT:": "TVA du panier :", "Finalize date": "Date de finalisation",
        "Fidelity client": "Client fidélité", "Walk-in client": "Client de passage", "Walk-in": "Passage",
        "Payment method": "Mode de paiement", "Payment Method": "Mode de paiement", "Payment reference": "Référence de paiement",
        "Money handed by client": "Montant remis par le client", "Ref / last 4 digits (optional)": "Réf. / 4 derniers chiffres (facultatif)",
        "Finalize and print receipt": "Finaliser et imprimer le reçu", "Finalise Sale": "Finaliser la vente", "Clear cart": "Vider le panier",
        "Clear Cart": "Vider le panier", "Sales history": "Historique des ventes", "Export sales CSV": "Exporter les ventes CSV",
        "Receipt": "Reçu", "Print": "Imprimer", "Back": "Retour", "Back to Products": "Retour aux produits", "n/a": "s.o.",
        "Cash": "Espèces", "Credit Card": "Carte bancaire", "Other": "Autre", "Reference": "Référence", "Total": "Total",
        "Subtotal": "Sous-total", "Discount": "Remise", "Change": "Monnaie", "Amount": "Montant",
        "Daily Sales Report": "Rapport des ventes quotidiennes", "Daily Purchases Report": "Rapport des achats quotidiens",
        "Daily Takings Report": "Rapport des recettes quotidiennes", "View report": "Voir le rapport", "All cashiers": "Tous les caissiers",
        "VAT": "TVA", "VAT Report": "Rapport TVA", "VAT Summary": "Résumé TVA", "Standard": "Standard", "Zero": "Taux zéro", "Exempt": "Exonéré",
        "Record purchase / stock in": "Enregistrer un achat / une entrée en stock", "Purchase date": "Date d'achat",
        "Generate & print barcodes": "Générer et imprimer des codes-barres", "Generate": "Générer", "Download": "Télécharger",
        "Decode barcode from image": "Décoder un code-barres depuis une image", "Upload image": "Téléverser une image", "Choose file": "Choisir un fichier",
        "Barcode decoder not available.": "Décodeur de codes-barres indisponible.", "No data available.": "Aucune donnée disponible.",
        "Cash Register Float": "Fond de caisse", "Open float": "Ouvrir le fond de caisse", "Close float": "Clôturer le fond de caisse",
        "Opening float": "Fond de caisse d'ouverture", "Closing float": "Fond de caisse de fermeture", "Expected cash": "Espèces attendues",
        "Actual cash": "Espèces réelles", "Difference": "Écart", "Cashier": "Caissier", "Customer": "Client",
        "Fidelity Clients": "Clients fidélité", "Client name": "Nom du client", "Phone": "Téléphone", "Email": "E-mail",
        "Points": "Points", "Total clients": "Nombre de clients", "Add client": "Ajouter un client",
        "Physical Stock Count": "Comptage physique du stock", "Stock Variance Report": "Rapport des écarts de stock",
        "Expected stock": "Stock théorique", "Counted stock": "Stock compté", "Variance": "Écart", "Low Stock": "Stock faible",
        "Database Maintenance": "Maintenance de la base de données", "Database Size": "Taille de la base de données",
        "Backup": "Sauvegarde", "Create Backup": "Créer une sauvegarde", "Purge": "Purger", "Save settings": "Enregistrer les paramètres",
        "Email address": "Adresse e-mail", "Save email settings": "Enregistrer les paramètres e-mail",
        "License Status": "Statut de la licence", "License is VALID": "La licence est VALIDE", "License is INVALID": "La licence est INVALIDE",
        "Status": "Statut", "Help & User Guide": "Aide et guide utilisateur", "Sales & POS": "Ventes et point de vente",
        "Quantity must be positive": "La quantité doit être positive", "Cart is empty": "Le panier est vide",
        "Current password is incorrect": "Le mot de passe actuel est incorrect", "User not found": "Utilisateur introuvable"
    };

    const translate = (text) => {
        if (typeof text !== "string") return text;
        const trimmed = text.trim();
        if (!trimmed) return text;
        let translated = dictionary[trimmed];
        if (!translated) {
            translated = trimmed
                .replace(/^Edit product: /, "Modifier le produit : ")
                .replace(/^Showing VAT data from (.+) to (.+)$/, "Données TVA affichées du $1 au $2")
                .replace(/^Showing data from (.+) to (.+)$/, "Données affichées du $1 au $2")
                .replace(/^Receipt #/, "Reçu n°")
                .replace(/^Change: Rs /, "Monnaie : Rs ")
                .replace(/^Short: Rs /, "Manque : Rs ")
                .replace(/^Remove (.+) from cart\?$/, "Retirer $1 du panier ?")
                .replace(/Monday/g, "Lundi").replace(/Tuesday/g, "Mardi").replace(/Wednesday/g, "Mercredi")
                .replace(/Thursday/g, "Jeudi").replace(/Friday/g, "Vendredi").replace(/Saturday/g, "Samedi")
                .replace(/Sunday/g, "Dimanche").replace(/January/g, "janvier").replace(/February/g, "février")
                .replace(/March/g, "mars").replace(/April/g, "avril").replace(/May/g, "mai").replace(/June/g, "juin")
                .replace(/July/g, "juillet").replace(/August/g, "août").replace(/September/g, "septembre")
                .replace(/October/g, "octobre").replace(/November/g, "novembre").replace(/December/g, "décembre");
        }
        return translated === trimmed ? text : text.replace(trimmed, translated);
    };

    const translateElement = (element) => {
        ["placeholder", "title", "aria-label", "value"].forEach((attribute) => {
            if (!element.hasAttribute(attribute)) return;
            const current = element.getAttribute(attribute);
            const translated = translate(current);
            if (translated !== current) element.setAttribute(attribute, translated);
        });
    };

    const translateNode = (node) => {
        if (node.nodeType === Node.TEXT_NODE) {
            const translated = translate(node.nodeValue);
            if (translated !== node.nodeValue) node.nodeValue = translated;
            return;
        }
        if (node.nodeType !== Node.ELEMENT_NODE || ["SCRIPT", "STYLE", "TEXTAREA"].includes(node.tagName)) return;
        translateElement(node);
        node.querySelectorAll("[placeholder], [title], [aria-label], input[type=submit], button").forEach(translateElement);
        const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
        const textNodes = [];
        while (walker.nextNode()) textNodes.push(walker.currentNode);
        textNodes.forEach(translateNode);
    };

    translateNode(document.body);
    const nativeConfirm = window.confirm.bind(window);
    window.confirm = (message) => nativeConfirm(translate(message));
    new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach(translateNode);
            if (mutation.type === "characterData") translateNode(mutation.target);
        });
    }).observe(document.body, { childList: true, characterData: true, subtree: true });
})();
