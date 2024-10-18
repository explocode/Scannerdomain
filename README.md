# Web Vulnerability Scanner
# credit : eliot by t.me/+Vh1gqRorPJwwNThk

Questo codice è uno scanner di vulnerabilità web che verifica vari aspetti di sicurezza di un dominio specificato dall'utente. Esegue controlli per identificare potenziali vulnerabilità nelle applicazioni web, inclusi:

1. **SQL Injection**: Verifica se il sito è vulnerabile a attacchi di iniezione SQL, in cui un attaccante può eseguire comandi SQL malevoli attraverso input non filtrati.

2. **Cross-Site Scripting (XSS)**: Controlla se il sito è vulnerabile a attacchi XSS, dove un attaccante può iniettare script malevoli che vengono eseguiti nel browser degli utenti.

3. **Cross-Site Request Forgery (CSRF)**: Verifica se il sito ha una protezione insufficiente contro attacchi CSRF, che sfruttano la fiducia di un sito nei confronti dell'utente.

4. **Misconfigurazione della sicurezza**: Controlla se ci sono configurazioni di sicurezza errate che potrebbero esporre il sito a rischi.

5. **Esposizione di dati sensibili**: Cerca la presenza di dati sensibili (come password e chiavi API) nel contenuto del sito.

6. **Open Redirect**: Verifica se il sito consente reindirizzamenti non autorizzati verso URL malevoli.

Il codice registra i risultati
