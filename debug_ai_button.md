# Guide de Débogage - Bouton AI Dashboard

## Étape 1: Vérifier la Console du Navigateur

1. Ouvrez le dashboard: http://localhost:5000/dashboard
2. Connectez-vous avec votre compte
3. Appuyez sur F12 pour ouvrir les outils de développement
4. Allez dans l'onglet "Console"
5. Cliquez sur le bouton "Generate AI Report"
6. Regardez les messages qui apparaissent dans la console

**Messages attendus:**
```
Starting AI analysis...
Device API response status: 200
Raw device data: [...]
Processed devices for AI: [...]
Making POST request to /ai-analysis...
```

**Messages d'erreur possibles:**
- `Failed to fetch device data` → Problème avec l'API des équipements
- `Request failed` → Problème avec la requête AI
- `TypeError` → Erreur JavaScript

## Étape 2: Vérifier l'onglet Réseau

1. Dans les outils de développement, allez dans l'onglet "Network"
2. Cliquez sur "Generate AI Report"
3. Cherchez la requête `/ai-analysis`
4. Vérifiez:
   - Status code (devrait être 200)
   - Request payload (devrait contenir les données des équipements)
   - Response (devrait contenir l'analyse AI)

## Étape 3: Tester avec la page de test

1. Allez sur: http://localhost:5000/test-ai
2. Cliquez sur "Generate AI Report"
3. Vérifiez si cela fonctionne dans la page de test

**Si la page de test fonctionne mais pas le dashboard:**
- Le problème est dans l'extraction des données du dashboard
- Regardez les logs dans la console pour comparer

## Étape 4: Vérifier manuellement

1. Ouvrez un nouvel onglet
2. Allez sur: http://localhost:5000/api/equipments/status
3. Vérifiez que vous voyez les données des équipements
4. Si vous voyez une erreur d'authentification, le problème est là

## Étape 5: Tester Ollama directement

```bash
curl -X POST http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3.2",
    "prompt": "What is 2+2?",
    "stream": false
  }'
```

## Solutions possibles

### Si l'API des équipements ne fonctionne pas:
```javascript
// Dans la console du navigateur, essayez:
fetch('/api/equipments/status', {
    method: 'GET',
    headers: { 'X-Requested-With': 'XMLHttpRequest' }
})
.then(r => r.json())
.then(data => console.log(data))
```

### Si l'AI endpoint ne fonctionne pas:
```javascript
// Test direct:
fetch('/ai-analysis', {
    method: 'POST',
    headers: { 
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
    },
    body: JSON.stringify({
        devices: [
            {ip: '192.168.1.1', status: 'UP', ports: [{port: 22, status: 'OPEN'}]}
        ]
    })
})
.then(r => r.json())
.then(data => console.log(data))
```

### Si Ollama ne fonctionne pas:
1. Vérifiez: `tasklist | findstr ollama`
2. Redémarrez: `ollama serve`
3. Testez: `ollama list`

## Rapport d'erreur

Quand vous contactez le support, incluez:
1. Les messages exacts de la console
2. Le status code des requêtes réseau
3. Les données envoyées/reçues
4. Une capture d'écran si possible
