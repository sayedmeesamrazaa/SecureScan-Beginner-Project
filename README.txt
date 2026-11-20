SECURESCAN - COMPLETE BEGINNER PROJECT

FEATURES
- VirusTotal-inspired frontend (HTML/CSS/JavaScript)
- File selection and drag-and-drop
- Frontend-to-backend file upload
- Backend calculates SHA-256
- URL validation and backend endpoint
- Optional VirusTotal API submission using a server-side API key

RUN
1. Extract this ZIP and open the ROOT folder in VS Code.
2. Open Terminal > New Terminal.
3. Run: cd backend
4. Run: npm install
5. Run: npm start
6. Keep that terminal open.
7. In VS Code Explorer, right-click the ROOT index.html (not backend/index.html) and choose Open with Live Server.
8. Test with a small, non-confidential file or a public URL.

DEMO MODE
Without a VirusTotal API key, file upload and URL validation work, but no malware scan is performed. The backend receives the file and calculates its SHA-256 only.

OPTIONAL VIRUSTOTAL API
1. Sign in to VirusTotal and obtain your API key from your account.
2. Copy backend/.env.example to backend/.env.
3. Put your key after VT_API_KEY= in backend/.env.
4. Save, stop the backend with Ctrl+C, then run npm start again.
5. Only submit files/URLs you are allowed to share. VirusTotal submissions may be shared with its security community/partners. Never submit confidential, personal, or sensitive files.
6. API access and rate limits depend on your VirusTotal account.

SECURITY
- Never put the API key in script.js or index.html.
- .env is excluded from Git by .gitignore.
- This student project is not a production antivirus product.
- Upload limit is 32 MB in this sample.
