const express = require("express");
const cors = require("cors");
const multer = require("multer");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.VT_API_KEY;
app.use(cors());
app.use(express.json());

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 32 * 1024 * 1024, files: 1 } });

app.get("/", (req,res) => res.send("SecureScan Backend is Running!"));
app.get("/api/status", (req,res) => res.json({ success:true, message:"SecureScan API is working!", virusTotalConfigured:Boolean(API_KEY) }));

app.post("/api/upload", upload.single("file"), async (req,res) => {
  try {
    if (!req.file) return res.status(400).json({ success:false, message:"Please select a file." });
    const sha256 = crypto.createHash("sha256").update(req.file.buffer).digest("hex");
    if (!API_KEY) return res.json({
      success:true, fileName:req.file.originalname, fileSize:req.file.size, sha256,
      scanStatus:"Received by backend — demo mode, not scanned",
      message:"To enable VirusTotal submission, add VT_API_KEY to backend/.env."
    });
    const form = new FormData();
    form.append("file", new Blob([req.file.buffer], {type:req.file.mimetype || "application/octet-stream"}), req.file.originalname);
    const vt = await fetch("https://www.virustotal.com/api/v3/files", { method:"POST", headers:{"x-apikey":API_KEY}, body:form });
    const data = await vt.json();
    if (!vt.ok) return res.status(vt.status).json({success:false,message:data.error?.message || "VirusTotal submission failed."});
    res.json({success:true,fileName:req.file.originalname,fileSize:req.file.size,sha256,scanStatus:"Submitted to VirusTotal; report may take time to appear.",analysisUrl:`https://www.virustotal.com/gui/file/${sha256}`});
  } catch(e) { console.error(e); res.status(500).json({success:false,message:"Server error while processing file."}); }
});

app.post("/api/url", async (req,res) => {
  try {
    let u; try { u = new URL(req.body?.url); } catch { return res.status(400).json({success:false,message:"Enter a valid URL."}); }
    if (!["http:","https:"].includes(u.protocol)) return res.status(400).json({success:false,message:"Only HTTP and HTTPS URLs are accepted."});
    if (!API_KEY) return res.json({success:true,url:u.href,scanStatus:"URL validated by backend — demo mode, not scanned",message:"To enable VirusTotal submission, add VT_API_KEY to backend/.env."});
    const body = new URLSearchParams({url:u.href});
    const vt = await fetch("https://www.virustotal.com/api/v3/urls",{method:"POST",headers:{"x-apikey":API_KEY,"Content-Type":"application/x-www-form-urlencoded"},body});
    const data = await vt.json();
    if (!vt.ok) return res.status(vt.status).json({success:false,message:data.error?.message || "VirusTotal URL submission failed."});
    const id = Buffer.from(u.href).toString("base64").replace(/=+$/,"");
    res.json({success:true,url:u.href,scanStatus:"Submitted to VirusTotal; report may take time to appear.",analysisUrl:`https://www.virustotal.com/gui/url/${id}`});
  } catch(e) { console.error(e); res.status(500).json({success:false,message:"Server error while submitting URL."}); }
});

app.use((err,req,res,next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({success:false,message:err.message});
  console.error(err); res.status(500).json({success:false,message:"Unexpected server error."});
});
app.listen(PORT,()=>console.log(`SecureScan server running at http://localhost:${PORT}`));
