


const firebaseConfig = {
    apiKey: "AIzaSyBGVB2Nuy63sS7cp_2YVQfnzpBDLzHvuJQ",
    authDomain: "certvalid-6175f.firebaseapp.com",
    projectId: "certvalid-6175f",
    storageBucket: "certvalid-6175f.firebasestorage.app",
    messagingSenderId: "1014352462680",
    appId: "1:1014352462680:web:22af91b5e85b941562db2d",
    measurementId: "G-TW0PXY0N4K"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();


const DB = {
    // 1. User Management
    saveUser: async (user) => {
        try {
            // user.id MUST be their Auth UID
            await db.collection('users').doc(user.id).set(user);
        } catch (e) {
            console.warn("Firestore save failed, using LocalStorage for User:", e.message);
            const localUsers = JSON.parse(localStorage.getItem('local_users') || '[]');
            const index = localUsers.findIndex(u => u.id === user.id);
            if (index !== -1) {
                localUsers[index] = user;
            } else {
                localUsers.push(user);
            }
            localStorage.setItem('local_users', JSON.stringify(localUsers));
        }
    },

    getUser: async (uid) => {
        try {
            const doc = await db.collection('users').doc(uid).get();
            if (doc.exists) return doc.data();
        } catch (e) { }

        const localUsers = JSON.parse(localStorage.getItem('local_users') || '[]');
        return localUsers.find(u => u.id === uid) || null;
    },

    getAllUsers: async () => {
        let firestoreUsers = [];
        try {
            const snapshot = await db.collection('users').get();
            firestoreUsers = snapshot.docs.map(doc => doc.data());
        } catch (e) {
            console.warn("Firestore read failed (Users), utilizing LocalStorage fallback");
        }

        const localUsers = JSON.parse(localStorage.getItem('local_users') || '[]');

        // Merge Firestore and LocalStorage (Local wins on conflict for dev purposes)
        const combined = new Map();
        firestoreUsers.forEach(u => combined.set(u.id, u));
        localUsers.forEach(u => combined.set(u.id, u));

        // If both empty and we had an error, throw to show the UI error message? 
        // No, better to show empty list than error if we have fallback support.
        // But if we want to prompt for Rules deployment, maybe we should let the permission error bubble IF local is empty?
        // Actually, let's return the list. If it's empty, the table shows "No users found".
        // If the user REALLY wants to see the permission error, this hides it, but it makes the app usable.
        // Let's stick to robustness.

        return Array.from(combined.values());
    },

    deleteUser: async (userId) => {
        // Delete from Firestore
        try {
            await db.collection('users').doc(userId).delete();
            console.log("Deleted user from Firestore:", userId);
        } catch (e) {
            console.warn("Firestore delete failed:", e.message);
        }

        // Delete from LocalStorage
        const localUsers = JSON.parse(localStorage.getItem('local_users') || '[]');
        const filtered = localUsers.filter(u => u.id !== userId);
        localStorage.setItem('local_users', JSON.stringify(filtered));
        console.log("Deleted user from LocalStorage:", userId);
    },

    // 2. Certificate Management
    addCertificate: async (cert) => {
        try {
            // Try Firestore with strict timeout
            const savePromise = db.collection('certificates').doc(cert.id).set(cert);
            const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 5000));
            await Promise.race([savePromise, timeoutPromise]);
        } catch (err) {
            console.warn("Firestore failed, using LocalStorage:", err);
            // Fallback to LocalStorage
            const localCerts = JSON.parse(localStorage.getItem('local_certs') || '[]');
            localCerts.push(cert);
            localStorage.setItem('local_certs', JSON.stringify(localCerts));
        }
    },

    getCertificatesByUser: async (userId) => {
        let firestoreData = [];
        try {
            const snapshot = await db.collection('certificates').where('userId', '==', userId).get();
            firestoreData = snapshot.docs.map(doc => doc.data());
        } catch (err) { console.warn("Firestore read failed, checking LocalStorage"); }

        // Merge with LocalStorage
        const localCerts = JSON.parse(localStorage.getItem('local_certs') || '[]');
        const userLocalCerts = localCerts.filter(c => c.userId === userId);

        // Return combined unique list (by ID)
        const combined = [...firestoreData, ...userLocalCerts];
        return Array.from(new Map(combined.map(item => [item.id, item])).values());
    },

    getAllCertificates: async () => {
        let firestoreData = [];
        try {
            const snapshot = await db.collection('certificates').get();
            firestoreData = snapshot.docs.map(doc => doc.data());
        } catch (e) { }

        const localCerts = JSON.parse(localStorage.getItem('local_certs') || '[]');
        const combined = [...firestoreData, ...localCerts];
        return Array.from(new Map(combined.map(item => [item.id, item])).values());
    },

    getCertificateById: async (id) => {
        try {
            const doc = await db.collection('certificates').doc(id).get();
            if (doc.exists) return doc.data();
        } catch (e) { }

        // Fallback
        const localCerts = JSON.parse(localStorage.getItem('local_certs') || '[]');
        return localCerts.find(c => c.id === id) || null;
    },

    updateCertificateStatus: async (id, status, txHash = null, issuer = null) => {
        const updates = { status };
        if (txHash) updates.txHash = txHash;
        if (issuer) updates.issuer = issuer;

        console.log(`[DB] Updating certificate ${id} status to ${status}`);

        // Try Firestore first
        let firestoreSuccess = false;
        try {
            await db.collection('certificates').doc(id).update(updates);
            console.log(`[DB] Firestore update successful for ${id}`);
            firestoreSuccess = true;
        } catch (e) {
            console.warn("[DB] Firestore update failed:", e.message);
        }

        // ALWAYS update LocalStorage (as fallback/sync)
        const localCerts = JSON.parse(localStorage.getItem('local_certs') || '[]');
        const index = localCerts.findIndex(c => c.id === id);
        if (index !== -1) {
            // Update existing
            localCerts[index] = { ...localCerts[index], ...updates };
            console.log(`[DB] LocalStorage updated for ${id}`);
        } else if (!firestoreSuccess) {
            // If not in LocalStorage AND Firestore failed, we need to fetch and store
            console.warn(`[DB] Certificate ${id} not in LocalStorage, attempting to sync`);
            try {
                const doc = await db.collection('certificates').doc(id).get();
                if (doc.exists) {
                    const cert = { ...doc.data(), ...updates };
                    localCerts.push(cert);
                    console.log(`[DB] Synced ${id} from Firestore to LocalStorage`);
                }
            } catch (e) {
                console.error("[DB] Failed to sync from Firestore");
            }
        }
        localStorage.setItem('local_certs', JSON.stringify(localCerts));
    },

    // Update certificate verification fields
    updateCertificateFields: async (id, fields) => {
        console.log(`[DB] Updating certificate ${id} fields:`, fields);

        const updates = {};
        if (fields.name) updates.name = fields.name;
        if (fields.registerNumber) updates.registerNumber = fields.registerNumber;
        if (fields.institution) updates.institution = fields.institution;
        if (fields.organizer) updates.organizer = fields.organizer;
        if (fields.degree) updates.degree = fields.degree;
        if (fields.fileHash) updates.fileHash = fields.fileHash;
        if (fields.year) updates.year = fields.year;
        updates.updatedAt = new Date().toISOString();

        // Update in Firestore
        try {
            await db.collection('certificates').doc(id).update(updates);
            console.log(`[DB] Firestore fields update successful for ${id}`);
        } catch (e) {
            console.warn("[DB] Firestore update failed:", e.message);
        }

        // Update in LocalStorage
        const localCerts = JSON.parse(localStorage.getItem('local_certs') || '[]');
        const index = localCerts.findIndex(c => c.id === id);
        if (index !== -1) {
            localCerts[index] = { ...localCerts[index], ...updates };
            localStorage.setItem('local_certs', JSON.stringify(localCerts));
            console.log(`[DB] LocalStorage updated for ${id}`);
        }

        return true;
    }
};

// Deprecated Storage Wrapper (Kept to avoid immediate crashes, but logic will shift to DB)
const Storage = {
    get: () => [],
    set: () => { }
};

const CONFIG = {
    // START: USER MUST UPDATE THESE
    CONTRACT_ADDRESS: "0xc530D241c6F1Efd3305a256C95a9e8ee83e2a352",
    PINATA_API_KEY: "YOUR_PINATA_KEY",
    PINATA_SECRET_KEY: "YOUR_PINATA_SECRET",
    // END
    SEPOLIA_CHAIN_ID: '0xaa36a7', // 11155111
    ALCHEMY_RPC: "https://eth-sepolia.g.alchemy.com/v2/jYiPgY_F3eTXH5Nrrie56"

};

const CONTRACT_ABI = [
    "function addCertificate(string _certificateId, string _ipfsHash, string _issuerName) public",
    "function verifyCertificate(string _certificateId) public view returns (string ipfsHash, string issuerName, address issuerAddress, uint256 issuedAt, bool exists)"
];
// READ-ONLY PROVIDER (for Public & Verifier access)
const READ_ONLY_PROVIDER = new ethers.providers.JsonRpcProvider(
    CONFIG.ALCHEMY_RPC
);


const Wallet = {
    provider: null,
    signer: null,
    address: null,
    isConnected: false,

    connect: async () => {
        if (!window.ethereum) {
            alert("MetaMask not found! Please install.");
            return;
        }

        try {
            await window.ethereum.request({ method: 'eth_requestAccounts' });
            const provider = new ethers.providers.Web3Provider(window.ethereum, "any");
            const { chainId } = await provider.getNetwork();

            if (chainId !== 11155111) {
                alert("Incorrect Network! Please switch to Sepolia.");
                try {
                    await window.ethereum.request({
                        method: 'wallet_switchEthereumChain',
                        params: [{ chainId: CONFIG.SEPOLIA_CHAIN_ID }],
                    });
                } catch (switchError) {
                    throw new Error("Please switch to Sepolia Network manually.");
                }
            }

            const signer = provider.getSigner();
            const address = await signer.getAddress();

            Wallet.provider = provider;
            Wallet.signer = signer;
            Wallet.address = address;
            Wallet.isConnected = true;

            console.log("Wallet Connected:", address);

            // UI Feedback
            const btn = document.getElementById('wallet-btn');
            if (btn) {
                btn.innerHTML = `<i class='bx bxs-wallet'></i> ${address.substring(0, 6)}...${address.substring(38)}`;
                btn.classList.add('btn-primary');
                btn.classList.remove('btn-secondary');
            }
            // alert("Wallet Connected Successfully!"); // Optional: overly intrusive if UI updates
            return address;
        } catch (err) {
            console.error(err);
            alert("Wallet Connection Failed: " + (err.message || err));
            throw new Error(err.message || "Wallet connection failed");
        }
    }
};

const Blockchain = {
    getContract: (withSigner = false) => {
        if (withSigner) {
            if (!Wallet.signer) {
                throw new Error("Signer required but wallet not connected");
            }
            return new ethers.Contract(CONFIG.CONTRACT_ADDRESS, CONTRACT_ABI, Wallet.signer);
        }

        // ALWAYS read-only for verifier/public
        return new ethers.Contract(
            CONFIG.CONTRACT_ADDRESS,
            CONTRACT_ABI,
            READ_ONLY_PROVIDER
        );
    },

    writeCertificate: async (id, hash, issuerName) => {
        try {
            if (!Wallet.isConnected) await Wallet.connect();
            const contract = Blockchain.getContract(true);
            const tx = await contract.addCertificate(id, hash, issuerName);
            return tx;
        } catch (err) {
            console.error("Blockchain Write Error:", err);
            throw err;
        }
    },

    verifyCertificate: async (id) => {
        try {
            const contract = Blockchain.getContract(false); // force read-only
            const data = await contract.verifyCertificate(id);

            if (!data.exists) return null;

            return {
                ipfsHash: data.ipfsHash,
                issuerName: data.issuerName,
                issuerAddress: data.issuerAddress,
                issuedAt: new Date(data.issuedAt.toNumber() * 1000).toLocaleString(),
                exists: data.exists
            };
        } catch (err) {
            throw new Error("Blockchain RPC unavailable. Please try again later.");
        }
    }
};

const IPFS = {
    upload: async (jsonData) => {
        // Use Mock if keys missing (Graceful Demo Fallback)
        if (CONFIG.PINATA_API_KEY.includes("YOUR_")) {
            console.warn("Using MOCK IPFS (No API Keys provided)");
            await new Promise(r => setTimeout(r, 1000));
            return "Qm" + Math.random().toString(36).substr(2, 10) + "MockHash";
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s Timeout

        const url = `https://api.pinata.cloud/pinning/pinJSONToIPFS`;
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'pinata_api_key': CONFIG.PINATA_API_KEY,
                    'pinata_secret_api_key': CONFIG.PINATA_SECRET_KEY
                },
                body: JSON.stringify(jsonData),
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            const result = await response.json();
            if (result.error) throw new Error(result.error);
            return result.IpfsHash;
        } catch (err) {
            clearTimeout(timeoutId);
            console.error("IPFS Upload Failed", err);
            if (err.name === 'AbortError') {
                throw new Error("IPFS Upload Timed Out. Please check your internet connection.");
            }
            throw new Error("IPFS Upload Failed: " + err.message);
        }
    },

    fetch: async (hash) => {
        try {
            // Fallback Gateways in case one fails
            const gateways = [
                `https://gateway.pinata.cloud/ipfs/${hash}`,
                `https://ipfs.io/ipfs/${hash}`,
                `https://dweb.link/ipfs/${hash}`
            ];

            for (const url of gateways) {
                try {
                    const response = await fetch(url);
                    if (response.ok) return await response.json();
                } catch (e) { console.warn("Gateway failed:", url); }
            }
            throw new Error("Could not fetch data from IPFS");
        } catch (err) {
            console.error("IPFS Fetch Error:", err);
            return null; // Return null gracefully
        }
    }
};

const API = {
    // Login with Firebase
    login: async (email, password) => {
        try {
            const userCredential = await auth.signInWithEmailAndPassword(email, password);
            // Return simplified user object for State
            const user = userCredential.user;
            const [name, role] = (user.displayName || "User|USER").split('|');
            return {
                id: user.uid,
                name: name,
                email: user.email,
                role: role
            };
        } catch (error) {
            console.error("Login Error:", error);
            throw error;
        }
    },

    // Register with Firebase
    register: async (userData) => {
        try {
            // Validate register number
            if (!userData.registerNumber || userData.registerNumber.trim() === '') {
                throw new Error('Register number is required');
            }

            const userCredential = await auth.createUserWithEmailAndPassword(userData.email, userData.password);
            const user = userCredential.user;

            // 1. Determine Role
            let role = 'USER';
            if (userData.email === 'admin@sys.com') {
                role = 'ADMIN';
            }

            // Store Role in Display Name
            await user.updateProfile({
                displayName: `${userData.name}|${role}`
            });

            // SAVE USER TO FIRESTORE (with register number)
            await DB.saveUser({
                id: user.uid,
                name: userData.name,
                email: user.email,
                registerNumber: userData.registerNumber.trim().toUpperCase(),
                role: role,
                createdAt: new Date().toISOString()
            });

            return {
                id: user.uid,
                name: userData.name,
                email: user.email,
                registerNumber: userData.registerNumber.trim().toUpperCase(),
                role: role
            };
        } catch (error) {
            console.error("Registration Error:", error);
            throw error;
        }
    },

    // Forgot Password
    forgotPassword: async (email) => {
        try {
            await auth.sendPasswordResetEmail(email);
        } catch (error) {
            console.error("Reset Password Error:", error);
            throw error;
        }
    },

    // Google Sign-In
    googleSignIn: async (selectedRole = 'USER') => {
        try {
            const provider = new firebase.auth.GoogleAuthProvider();
            provider.addScope('email');
            provider.addScope('profile');

            const result = await auth.signInWithPopup(provider);
            const user = result.user;

            // Check if user exists in Firestore
            const existingUser = await DB.getUser(user.uid);

            if (existingUser) {
                // User exists, return their data
                return {
                    id: user.uid,
                    name: existingUser.name,
                    email: user.email,
                    role: existingUser.role
                };
            } else {
                // New user - create profile with selected role
                const name = user.displayName || user.email.split('@')[0];
                const role = selectedRole;

                // Update Firebase displayName with role
                await user.updateProfile({
                    displayName: `${name}|${role}`
                });

                // Save to Firestore
                await DB.saveUser({
                    id: user.uid,
                    name: name,
                    email: user.email,
                    role: role
                });

                return {
                    id: user.uid,
                    name: name,
                    email: user.email,
                    role: role
                };
            }
        } catch (error) {
            console.error("Google Sign-In Error:", error);
            throw error;
        }
    },

    // Create New Admin (Without Logging Out Current User)
    createAdminUser: async (name, email, password) => {
        // 1. Initialize Secondary App
        const secondaryApp = firebase.initializeApp(firebaseConfig, "SecondaryApp");

        try {
            // 2. Create User on Secondary App
            const userCredential = await secondaryApp.auth().createUserWithEmailAndPassword(email, password);
            const user = userCredential.user;

            // 3. Update Profile
            await user.updateProfile({ displayName: `${name}|ADMIN` });

            // 4. Save to Firestore (Using System DB connection)
            await DB.saveUser({
                id: user.uid,
                name: name,
                email: email,
                role: 'ADMIN', // Enforced
                createdAt: new Date().toISOString()
            });

            // 5. Cleanup
            await secondaryApp.auth().signOut();
            await secondaryApp.delete();

            return true;

        } catch (error) {
            await secondaryApp.delete(); // Ensure cleanup
            throw error;
        }
    },

    ocrExtract: async (imageInput) => {
        console.log(`[OCR] Starting certificate information extraction pipeline...`);

        // ============================================================
        // 1. PRIMARY EXTRACTION: GOOGLE GEMINI VISION API (via Backend)
        // ============================================================
        try {
            console.log(`[GEMINI] Sending certificate to Node.js backend (/api/ocr)...`);

            let backendUrl = '/api/ocr';
            if (window.location.protocol === 'file:' || (window.location.port && window.location.port !== '5000')) {
                backendUrl = 'http://localhost:5000/api/ocr';
            }

            const response = await fetch(backendUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ image: imageInput })
            });

            if (response.ok) {
                const resData = await response.json();
                if (resData && resData.success && resData.data) {
                    const d = resData.data;
                    console.log(`[GEMINI] ✅ Response received & parsed successfully:`, d);

                    const yearMatch = (d.date && d.date.match(/\b(20\d{2}|19\d{2})\b/));
                    const yearVal = yearMatch ? yearMatch[1] : new Date().getFullYear().toString();

                    const result = {
                        name: d.name || "",
                        registerNumber: d.registerNumber || d.certificateId || "",
                        certificateId: d.certificateId || d.registerNumber || "",
                        institution: d.institution || "",
                        organizer: d.organizer || "",
                        degree: d.course || "",
                        course: d.course || "",
                        year: yearVal,
                        date: d.date || "",
                        gpa: "",
                        ocrSource: "gemini"
                    };

                    console.log(`[GEMINI] Extracted structured fields:`, result);
                    return result;
                }
            } else {
                const errText = await response.text();
                console.warn(`[GEMINI] Backend returned HTTP ${response.status}: ${errText}. Falling back to Tesseract OCR...`);
            }
        } catch (geminiError) {
            console.warn(`[GEMINI] Backend unavailable (${geminiError.message}). Falling back to local Tesseract OCR...`);
        }

        // ============================================================
        // 2. FALLBACK EXTRACTION: TESSERACT.JS OCR PIPELINE
        // ============================================================
        console.log(`[OCR] Running local Tesseract.js fallback pipeline...`);

        if (!window.Tesseract) {
            console.warn("[OCR] Tesseract.js not loaded. Please check internet connection.");
            return { name: "", registerNumber: "", certificateId: "", institution: "", organizer: "", degree: "", course: "", year: new Date().getFullYear().toString(), date: "", gpa: "", ocrSource: "failed" };
        }

        // Helper to load image from source URL/base64
        const loadImage = (src) => {
            return new Promise((resolve, reject) => {
                const img = new Image();
                img.crossOrigin = "anonymous";
                img.onload = () => resolve(img);
                img.onerror = (err) => reject(new Error("Failed to load image for OCR preprocessing: " + err));
                img.src = src;
            });
        };

        // Canvas preprocessor with multi-filter enhancements (grayscale, contrast stretching, sharpening, binarization)
        const preprocessCanvas = (img, filterMode = 'enhanced') => {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');

            // 1. Resolution Normalization: Upscale low-res images for sharper OCR
            let width = img.width || img.naturalWidth;
            let height = img.height || img.naturalHeight;
            let scale = 1.0;

            if (width < 1800) {
                scale = Math.min(3.0, 2000 / width);
            } else if (width > 3200) {
                scale = 2400 / width;
            }

            canvas.width = Math.round(width * scale);
            canvas.height = Math.round(height * scale);

            ctx.imageSmoothingEnabled = true;
            ctx.imageSmoothingQuality = 'high';
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const data = imgData.data;
            const len = data.length;

            if (filterMode === 'enhanced' || filterMode === 'sharpen') {
                // Step A: Grayscale with standard luminance weights
                const gray = new Uint8ClampedArray(len / 4);
                let min = 255;
                let max = 0;

                for (let i = 0, j = 0; i < len; i += 4, j++) {
                    // Standard Rec. 601 Luma
                    const luma = Math.round(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
                    gray[j] = luma;
                    if (luma < min) min = luma;
                    if (luma > max) max = luma;
                }

                // Step B: Adaptive Contrast Stretching (Histogram normalization)
                const range = (max - min) || 1;
                for (let i = 0, j = 0; i < len; i += 4, j++) {
                    const stretched = Math.round(((gray[j] - min) / range) * 255);
                    data[i] = stretched;
                    data[i + 1] = stretched;
                    data[i + 2] = stretched;
                    // data[i+3] is alpha (unchanged)
                }

                ctx.putImageData(imgData, 0, 0);

                // Step C: Apply Sharpening Convolution Filter for blurry/low-contrast text
                if (filterMode === 'sharpen') {
                    const sharpData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    const sData = sharpData.data;
                    const w = canvas.width;
                    const h = canvas.height;
                    const copy = new Uint8ClampedArray(sData);

                    // 3x3 unsharp sharpening kernel: [0, -0.5, 0, -0.5, 3.0, -0.5, 0, -0.5, 0]
                    for (let y = 1; y < h - 1; y++) {
                        for (let x = 1; x < w - 1; x++) {
                            const idx = (y * w + x) * 4;
                            const top = ((y - 1) * w + x) * 4;
                            const bottom = ((y + 1) * w + x) * 4;
                            const left = (y * w + (x - 1)) * 4;
                            const right = (y * w + (x + 1)) * 4;

                            const val = (3.0 * copy[idx]) - (0.5 * (copy[top] + copy[bottom] + copy[left] + copy[right]));
                            const clamped = Math.min(255, Math.max(0, val));
                            sData[idx] = clamped;
                            sData[idx + 1] = clamped;
                            sData[idx + 2] = clamped;
                        }
                    }
                    ctx.putImageData(sharpData, 0, 0);
                }
            } else if (filterMode === 'binarize') {
                // Adaptive / Otsu-like Thresholding for colored backgrounds / stamps
                let sum = 0;
                const gray = new Uint8ClampedArray(len / 4);
                for (let i = 0, j = 0; i < len; i += 4, j++) {
                    const luma = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
                    gray[j] = luma;
                    sum += luma;
                }
                const avg = sum / (len / 4);
                const threshold = avg * 0.88; // Slightly biased towards background removal

                for (let i = 0, j = 0; i < len; i += 4, j++) {
                    const val = gray[j] > threshold ? 255 : 0;
                    data[i] = val;
                    data[i + 1] = val;
                    data[i + 2] = val;
                }
                ctx.putImageData(imgData, 0, 0);
            }

            return canvas.toDataURL('image/png');
        };

        try {
            let processedImages = [];
            let extractedNativeText = "";

            // ============================================================
            // 2. INPUT NORMALIZATION & MULTI-PAGE PDF HANDLING
            // ============================================================
            const isPdf = typeof imageInput === 'string' &&
                (imageInput.includes('application/pdf') || imageInput.startsWith('JVBER') || imageInput.startsWith('data:application/pdf'));

            if (isPdf) {
                console.log("[OCR] PDF detected. Processing pages & extracting text layers...");
                if (!window.pdfjsLib) {
                    throw new Error("PDF.js library not loaded. Cannot process PDF document.");
                }

                let pdfBase64 = imageInput;
                if (imageInput.includes(',')) {
                    pdfBase64 = imageInput.split(',')[1];
                }

                const pdfData = atob(pdfBase64);
                const pdfArray = new Uint8Array(pdfData.length);
                for (let i = 0; i < pdfData.length; i++) {
                    pdfArray[i] = pdfData.charCodeAt(i);
                }

                const pdf = await pdfjsLib.getDocument({ data: pdfArray }).promise;
                const totalPages = Math.min(pdf.numPages, 5); // Process up to 5 pages
                console.log(`[OCR] PDF loaded successfully with ${pdf.numPages} page(s). Processing ${totalPages} page(s)...`);

                for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
                    const page = await pdf.getPage(pageNum);

                    // Try native PDF text layer first (100% precision for digital PDFs)
                    try {
                        const textContent = await page.getTextContent();
                        if (textContent && textContent.items && textContent.items.length > 0) {
                            const pageNativeText = textContent.items.map(item => item.str).join(' ');
                            if (pageNativeText.trim().length > 30) {
                                extractedNativeText += " \n " + pageNativeText;
                                console.log(`[OCR] Extracted native vector text from PDF page ${pageNum} (${pageNativeText.length} chars)`);
                            }
                        }
                    } catch (e) {
                        console.warn(`[OCR] Native text extraction skipped for page ${pageNum}:`, e);
                    }

                    // Render page at high DPI for image OCR
                    const scale = 2.5; // High resolution rendering
                    const viewport = page.getViewport({ scale });
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = viewport.width;
                    canvas.height = viewport.height;

                    await page.render({
                        canvasContext: ctx,
                        viewport: viewport
                    }).promise;

                    processedImages.push(canvas.toDataURL('image/png'));
                }
            } else {
                // Input is standard image (PNG, JPG, WebP, etc.)
                processedImages.push(imageInput);
            }

            // ============================================================
            // 3. MULTI-PASS OCR RECOGNITION
            // ============================================================
            let combinedOcrText = extractedNativeText || "";

            for (let i = 0; i < processedImages.length; i++) {
                const rawImgSrc = processedImages[i];
                let loadedImg;
                try {
                    loadedImg = await loadImage(rawImgSrc);
                } catch (imgLoadErr) {
                    console.warn("[OCR] Error loading image for canvas preprocessing:", imgLoadErr);
                }

                // Pass 1: Enhanced Grayscale + Sharpened
                const enhancedSrc = loadedImg ? preprocessCanvas(loadedImg, 'sharpen') : rawImgSrc;

                console.log(`[OCR] Running Tesseract recognition on image/page ${i + 1}...`);
                const { data: { text, confidence } } = await Tesseract.recognize(
                    enhancedSrc,
                    'eng',
                    { logger: m => console.log(`[OCR P${i + 1}] ${m.status}: ${Math.round((m.progress || 0) * 100)}%`) }
                );

                console.log(`[OCR Page ${i + 1} Raw Text] (Confidence: ${confidence}%):\n`, text);
                combinedOcrText += " \n " + text;

                // Fallback Pass 2: If confidence is very low (< 50) and image was preprocessed, try binarized pass
                if (confidence < 50 && loadedImg) {
                    console.log(`[OCR] Low confidence (${confidence}%). Running secondary binarized pass...`);
                    const binarizedSrc = preprocessCanvas(loadedImg, 'binarize');
                    try {
                        const pass2Result = await Tesseract.recognize(binarizedSrc, 'eng');
                        if (pass2Result && pass2Result.data && pass2Result.data.text) {
                            console.log(`[OCR Page ${i + 1} Pass 2 Text]:\n`, pass2Result.data.text);
                            combinedOcrText += " \n " + pass2Result.data.text;
                        }
                    } catch (p2Err) {
                        console.warn("[OCR] Pass 2 failed:", p2Err);
                    }
                }
            }

            // ============================================================
            // 4. TEXT NORMALIZATION & PREPARATION
            // ============================================================
            const rawCombined = combinedOcrText;
            // Clean up strange OCR glyphs & artifacts
            const sanitizedText = rawCombined
                .replace(/[\u2018\u2019\u201A\u201B]/g, "'")
                .replace(/[\u201C\u201D\u201E\u201F]/g, '"')
                .replace(/[|]/g, ' ')
                .replace(/[—–]/g, '-');

            const fullText = sanitizedText.replace(/\r?\n/g, ' ').replace(/\s+/g, ' ').trim();
            const lines = sanitizedText
                .split('\n')
                .map(l => l.replace(/\s+/g, ' ').trim())
                .filter(l => l.length > 2);

            console.log("[OCR Cleaned FullText]:", fullText);
            console.log("[OCR Lines Array]:", lines);

            // ============================================================
            // 5. SMART ENTITY EXTRACTION ENGINE
            // ============================================================

            // Helper: Clean extracted string
            const cleanString = (str) => {
                if (!str) return "";
                return str
                    .replace(/^[\s\:\-\.\,\;\"\'\(\)]+/, '')
                    .replace(/[\s\:\-\.\,\;\"\'\(\)]+$/, '')
                    .replace(/\s+/g, ' ')
                    .trim();
            };

            // Helper: Clean Person Name
            const cleanName = (str) => {
                if (!str) return "";
                let res = str
                    .replace(/^(?:This\s+(?:is\s+to\s+)?certif(?:y|ies|ied)\s+that|This\s+certificate\s+is\s+(?:proudly\s+)?presented\s+to|Proudly\s+presented\s+to|Presented\s+to|Awarded\s+to|Conferred\s+upon|Given\s+to|Honors\s+bestowed\s+on|Certifies\s+that)\s*/i, '')
                    .replace(/^(?:Mr\.?|Ms\.?|Mrs\.?|Miss\.?|Dr\.?|Prof\.?|Shri\.?|Smt\.?|Mx\.?|Master)\s*/i, '')
                    .replace(/^(?:Mr\.?\s*\/\s*Ms\.?|Ms\.?\s*\/\s*Mr\.?|Mr\s*\/\s*Ms)\s*/i, '')
                    .replace(/^(?:Candidate|Student|Participant|Recipient|Awardee)?\s*Name\s*[:\-\.]*\s*/i, '')
                    .replace(/\s+(?:of|from|bearing|with|having|holding|son\s+of|daughter\s+of|student\s+of|a\s+student|for|has|in|who|successfully|participated|completed|attended|secured|awarded|representing|dated|on|during|the|and)\b.*$/i, '')
                    .replace(/[\d\:\;\(\)\[\]\{\}\*\#\$\@\^\_\+\=\<\>\/\\]/g, '')
                    .replace(/\s+/g, ' ')
                    .trim();

                // Strip leading/trailing non-letters
                res = res.replace(/^[^a-zA-Z]+/, '').replace(/[^a-zA-Z\.]+$/, '').trim();
                return res;
            };

            // Helper: Clean Institution Name
            const cleanInstitution = (str) => {
                if (!str) return "";
                let res = str
                    .replace(/^(?:student\s+of|studying\s+(?:in|at)|from|of|at)\s+/i, '')
                    .replace(/\s+(?:has\s+participated|has\s+completed|has\s+attended|participated|completed|attended|for|on|in|during|dated|with|bearing|held\s+at)\b.*$/i, '')
                    .replace(/^(?:institution|college|university|school)\s*[:\-\.]*\s*/i, '')
                    .replace(/[\:\;\(\)\[\]\{\}\*\#\$\@\^\_\+\=\<\>]/g, '')
                    .replace(/\s+/g, ' ')
                    .trim();

                res = res.replace(/^[^a-zA-Z]+/, '').replace(/[^a-zA-Z\.\)]+$/, '').trim();
                return res;
            };

            let name = "";
            let institution = "";
            let organizer = "";
            let degree = "";
            let registerNumber = "";
            let year = "";
            let gpa = "";

            // ------------------------------------------------------------
            // A. NAME EXTRACTION (Multi-Pattern & Line Heuristics)
            // ------------------------------------------------------------

            const namePatterns = [
                // Pattern 1: Explicit labels like "Name: JOHN DOE" or "Student Name: CHANDRU T"
                /(?:(?:Candidate|Student|Participant|Recipient|Awardee)?\s*Name)\s*[:\-\.\|]\s*([A-Z][A-Za-z\s\.\'\`\-]{2,45})/i,

                // Pattern 2: "Mr./Ms. NAME" or combined slash format "Mr./Ms. KIRUTHIGA N"
                /(?:Mr\.?\s*\/\s*Ms\.?|Ms\.?\s*\/\s*Mr\.?|Mr\s*\/\s*Ms)\s+([A-Z][A-Za-z\s\.\'\`\-]{2,40}?)(?=\s+(?:of|from|bearing|with|having|student|for|has|in|who|participated|\,|\.|\n|$))/i,

                // Pattern 3: Standard Titles: "Mr. AKSHAY ANAND M P" or "Ms. SARAH CONNOR"
                /(?:Mr\.?|Ms\.?|Mrs\.?|Miss\.?|Dr\.?|Prof\.?|Shri\.?|Smt\.?|Mx\.?)\s+([A-Z][A-Za-z\s\.\'\`\-]{2,40}?)(?=\s+(?:of|from|bearing|with|having|student|for|has|in|who|participated|\,|\.|\n|$))/i,

                // Pattern 4: "certify that [Title] NAME of/from/bearing"
                /(?:certif(?:y|ies|ied)\s+that|certifies\s+that)\s+(?:(?:Mr\.?|Ms\.?|Mrs\.?|Miss\.?|Dr\.?|Prof\.?|Shri\.?|Smt\.?|Mr\.?\s*\/\s*Ms\.?)\s*)?([A-Z][A-Za-z\s\.\'\`\-]{2,45}?)(?=\s+(?:of|from|bearing|with|having|student|a\s+student|son\s+of|daughter\s+of|for|has|who|successfully|\,|\.|\n|$))/i,

                // Pattern 5: "presented to / awarded to / conferred upon NAME"
                /(?:presented\s+to|awarded\s+to|conferred\s+upon|given\s+to|proudly\s+presented\s+to|honors\s+bestowed\s+on)\s+(?:(?:Mr\.?|Ms\.?|Mrs\.?|Miss\.?|Dr\.?|Prof\.?|Shri\.?|Smt\.?|Mr\.?\s*\/\s*Ms\.?)\s*)?([A-Z][A-Za-z\s\.\'\`\-]{2,45}?)(?=\s+(?:of|from|bearing|with|having|student|for|has|in|who|successfully|a\s+student|\,|\.|\n|$))/i,

                // Pattern 6: Name immediately preceding register number ("AKSHAY ANAND bearing Reg No...")
                /([A-Z][A-Za-z\s\.\'\`\-]{2,40}?)\s+(?:bearing|with|having|holding)\s+(?:Reg(?:ister)?|Roll|ID|Enrollment|USN)/i
            ];

            for (const pat of namePatterns) {
                const match = fullText.match(pat);
                if (match && match[1]) {
                    const cleaned = cleanName(match[1]);
                    // Filter out invalid phrases (e.g. institution or cert words)
                    if (cleaned.length >= 2 && !/certificate|participation|technology|college|university|institute|department|workshop|bootcamp/i.test(cleaned)) {
                        name = cleaned;
                        break;
                    }
                }
            }

            // Fallback: Line-by-line inspection for standalone recipient name
            if (!name) {
                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i];
                    // Skip obvious header, metadata, or footer lines
                    if (/college|university|institute|technology|department|centre|center|conducted|organized|association|academy|school/i.test(line)) continue;
                    if (/certificate|participation|appreciation|completion|achievement|excellence|merit|attendance|recognition/i.test(line)) continue;
                    if (/\b(20\d{2}|january|february|march|april|may|june|july|august|september|october|november|december|date|reg\s*no|roll\s*no|id\s*no)\b/i.test(line)) continue;
                    if (/\d{4,}/.test(line)) continue;

                    // Standalone ALL CAPS name line (e.g., "CHANDRU T" or "KIRUTHIGA N" or "AKSHAY ANAND M P")
                    const allCapsMatch = line.match(/^([A-Z][A-Z\s\.]{2,35})$/);
                    if (allCapsMatch) {
                        const cleaned = cleanName(allCapsMatch[1]);
                        if (cleaned.length >= 2 && !/CERTIFICATE|COLLEGE|UNIVERSITY|INSTITUTE|TECHNOLOGY|DEPARTMENT|WORKSHOP|BOOTCAMP|PROGRAMME|PROJECT/i.test(cleaned)) {
                            name = cleaned;
                            break;
                        }
                    }

                    // Standalone Title Case name line (e.g., "John Doe" or "Kiruthiga N")
                    const titleCaseMatch = line.match(/^([A-Z][a-z]+(?:\s+[A-Z][a-zA-Z\.]*){1,4})$/);
                    if (titleCaseMatch) {
                        const cleaned = cleanName(titleCaseMatch[1]);
                        if (cleaned.length >= 3 && !/Certificate|Participation|Appreciation|Completion|Technology|College|University/i.test(cleaned)) {
                            name = cleaned;
                            break;
                        }
                    }
                }
            }

            // ------------------------------------------------------------
            // B. INSTITUTION EXTRACTION (Affiliation / College / University)
            // ------------------------------------------------------------

            const instPatterns = [
                // Pattern 1: "of / from Dr.N.G.P. Institute of Technology"
                /(?:student\s+of|studying\s+(?:in|at)|of|from)\s+((?:Dr\.?\s*)?[A-Z0-9\.\s\&\'\-]{2,50}?(?:Institute|College|University|Polytechnic|Academy|School|Faculty|Campus)(?:\s+of\s+[A-Za-z0-9\s\&]+)?)/i,

                // Pattern 2: "Dr.N.G.P. Institute of Technology" or "PSG College of Technology"
                /\b((?:Dr\.?\s*)?(?:[A-Z]\.?\s*){1,5}(?:Institute|College|University|Polytechnic|Academy)(?:\s+of\s+[A-Za-z0-9\s\&]+)?)/i,

                // Pattern 3: Header institution in ALL CAPS (e.g., "PSG COLLEGE OF TECHNOLOGY")
                /\b([A-Z0-9\.\s\&\'\-]{3,45}\s+(?:COLLEGE|INSTITUTE|UNIVERSITY|POLYTECHNIC|ACADEMY)(?:\s+OF\s+[A-Z0-9\s\&]+)?)\b/,

                // Pattern 4: Generic "student of XYZ"
                /student\s+of\s+([A-Z][A-Za-z0-9\.\s\&\'\-]{3,60})/i
            ];

            for (const pat of instPatterns) {
                const match = fullText.match(pat);
                if (match && match[1]) {
                    const cleaned = cleanInstitution(match[1]);
                    if (cleaned.length >= 6 && !/certificate|participation|appreciation|completion|achievement/i.test(cleaned)) {
                        institution = cleaned;
                        break;
                    }
                }
            }

            // Header scan fallback: Top 5 lines often contain the main institution
            if (!institution) {
                for (let i = 0; i < Math.min(lines.length, 6); i++) {
                    const line = lines[i];
                    if (/(?:College|University|Institute|Polytechnic|Academy|School|Campus)/i.test(line)) {
                        const cleaned = cleanInstitution(line);
                        if (cleaned.length >= 6 && !/certificate|this is to certify|presents/i.test(cleaned)) {
                            institution = cleaned;
                            break;
                        }
                    }
                }
            }

            // ------------------------------------------------------------
            // C. ORGANIZER / DEPARTMENT EXTRACTION
            // ------------------------------------------------------------

            const orgPatterns = [
                // Pattern 1: "conducted at/by [Institution/Department]"
                /(?:conducted|organized|organised|hosted|sponsored|coordinated)\s+(?:at|by)\s+(?:the\s+)?((?:Dr\.?\s*)?[A-Za-z0-9\.\s\&\,\'\-]{3,60}?(?:College|University|Institute|Technology|Department|Centre|Center|Association|Club|Division|School)(?:\s+of\s+[A-Za-z0-9\s\&]+)?)/i,

                // Pattern 2: "Department of Computer Science..." / "Centre for IoT..."
                /((?:Department|Dept\.?|Centre|Center|Division|School)\s+(?:of|for)\s+[A-Za-z0-9\s\&\-\/]{3,50})/i,

                // Pattern 3: "Centre for IoT, MIT Campus..."
                /((?:C-IoT|Centre\s+for\s+[^,]+),?\s*(?:MIT\s+Campus|[A-Z0-9\s]+\s+Campus)[^,\n]*)/i,

                // Pattern 4: "in association with XYZ"
                /(?:in\s+association\s+with|in\s+collaboration\s+with)\s+([A-Za-z0-9\s\&\,\.\-]+)/i
            ];

            for (const pat of orgPatterns) {
                const match = fullText.match(pat);
                if (match && match[1]) {
                    const cleaned = cleanString(match[1])
                        .replace(/\s+(?:on|from|in|the|during|held|dated)\s*$/i, '')
                        .replace(/[,.]$/, '')
                        .trim();
                    if (cleaned.length >= 4) {
                        organizer = cleaned;
                        break;
                    }
                }
            }

            // ------------------------------------------------------------
            // D. DEGREE / COURSE / EVENT / CERTIFICATE TITLE EXTRACTION
            // ------------------------------------------------------------

            const degreePatterns = [
                // Pattern 1: "edition of AXIOS" or similar event name
                /(?:edition\s+of|event\s+named|fest\s+titled)\s+([A-Z0-9\s\-\&]{2,30})/i,

                // Pattern 2: Detailed workshop / training format: "FIVE-DAY HANDS-ON WORKSHOP ON IOT DEVICE PROGRAMMING"
                /((?:FIVE|FOUR|THREE|TWO|ONE|\d+)[\s-]?DAY[S]?\s+(?:HANDS[\s-]?ON\s+)?(?:WORKSHOP|TRAINING|COURSE|BOOTCAMP|SEMINAR|CONFERENCE|FACULTY DEVELOPMENT PROGRAM|FDP|INTERNSHIP|HACKATHON)\s+(?:ON|IN|TITLED)\s+["']?([A-Za-z0-9\s\-&:\.\,\'\(\)]+?)["']?)(?=\s+(?:organized|conducted|held|from|on|at|by|\,|\.|\n|$))/i,

                // Pattern 3: "WORKSHOP / TRAINING / BOOTCAMP ON [TOPIC]"
                /(?:(?:HANDS[\s-]?ON\s+)?(?:WORKSHOP|TRAINING|BOOTCAMP|COURSE|SEMINAR|CONFERENCE|WEBINAR|HACKATHON|INTERNSHIP|CERTIFICATION)\s+(?:ON|IN|TITLED)\s+["']?([A-Za-z0-9\s\-&:\.\,\'\(\)]+?)["']?)/i,

                // Pattern 4: Academic Degree "Bachelor of Technology in Computer Science", "Master of Business Administration"
                /(?:Degree\s+of\s+)?\b((?:Bachelor|Master|Doctor|Diploma)\s+of\s+[A-Za-z0-9\s\&]+(?:\s+in\s+[A-Za-z0-9\s\&]+)?)/i,

                // Pattern 5: Degree Acronyms "B.E. Computer Science", "B.Tech Information Technology"
                /\b((?:B\.?E\.?|B\.?Tech\.?|M\.?E\.?|M\.?Tech\.?|B\.?Sc\.?|M\.?Sc\.?|B\.?Com\.?|M\.?Com\.?|B\.?B\.?A\.?|M\.?B\.?A\.?|B\.?C\.?A\.?|M\.?C\.?A\.?|Ph\.?D\.?)\s*(?:in\s+[A-Za-z0-9\s\&]+)?)\b/i,

                // Pattern 6: "for successfully completing / participating in the [EVENT/TOPIC]"
                /(?:for\s+(?:successfully\s+)?(?:participating|completing|attending|presenting\s+(?:a\s+paper\s+on)?)\s+(?:in\s+)?(?:the\s+)?(?:event\s+)?["']?([A-Za-z0-9\s\-&:\.\,\'\(\)]+?)["']?)(?=\s+(?:held|organized|conducted|from|on|at|dated|\,|\.|\n|$))/i,

                // Pattern 7: "CERTIFICATE OF PARTICIPATION / APPRECIATION / COMPLETION"
                /(CERTIFICATE\s+OF\s+(?:PARTICIPATION|APPRECIATION|COMPLETION|ACHIEVEMENT|EXCELLENCE|MERIT|RECOGNITION|HONOUR|ATTENDANCE))/i
            ];

            for (const pat of degreePatterns) {
                const match = fullText.match(pat);
                if (match) {
                    let matchedDegree = match[1] || match[0];
                    if (match[2]) {
                        matchedDegree = `${match[1]}`;
                    }
                    matchedDegree = cleanString(matchedDegree).replace(/["']/g, '');
                    if (matchedDegree.length >= 4) {
                        degree = matchedDegree;
                        break;
                    }
                }
            }

            // Degree Fallbacks from keywords
            if (!degree) {
                if (/hands[\s-]?on\s+workshop/i.test(fullText)) {
                    degree = "Hands-on Workshop";
                } else if (/workshop/i.test(fullText)) {
                    degree = "Workshop";
                } else if (/bootcamp/i.test(fullText)) {
                    degree = "Bootcamp";
                } else if (/training\s+program/i.test(fullText)) {
                    degree = "Training Program";
                } else if (/internship/i.test(fullText)) {
                    degree = "Internship";
                } else if (/certificate\s+of\s+participation/i.test(fullText)) {
                    degree = "Certificate of Participation";
                } else if (/certificate\s+of\s+appreciation/i.test(fullText)) {
                    degree = "Certificate of Appreciation";
                } else if (/certificate\s+of\s+completion/i.test(fullText)) {
                    degree = "Certificate of Completion";
                }
            }

            // ------------------------------------------------------------
            // E. REGISTER / CERTIFICATE / ROLL NUMBER EXTRACTION
            // ------------------------------------------------------------

            const regPatterns = [
                // Explicit labels: "Reg No: 2025W020034", "Certificate No: CERT-12345", "Roll No: 19BCS042"
                /(?:Certificate\s*(?:No|Num|Number|ID|\#)?|Cert\s*ID|Reg(?:ister|istration)?\s*(?:No|Num|Number|\#)?|Roll\s*(?:No|Number|\#)?|Enrollment\s*(?:No|Number|\#)?|USN|PRN|Student\s*ID|Serial\s*(?:No|Number|\#)?|Ref\s*(?:No)?|Credential\s*ID)\s*[:\-\.\#\s]\s*([A-Z0-9\-\/\_]{3,30})/i,

                // University style student codes: "2025W020034", "2021BCS042", "717821P123"
                /\b([0-9]{2,4}[A-Z]{1,5}[0-9]{3,8})\b/,

                // University register codes starting with 20: "2025W020034"
                /\b(20\d{2}[A-Z0-9\-\/]{4,20})\b/,

                // Standard certificate format: "CERT-526001" or "ID-883921"
                /\b([A-Z]{3,6}\-[0-9]{4,10})\b/
            ];

            for (const pat of regPatterns) {
                const match = fullText.match(pat);
                if (match && match[1]) {
                    const cleaned = cleanString(match[1]);
                    if (cleaned.length >= 3 && !/college|institute|university|workshop/i.test(cleaned)) {
                        registerNumber = cleaned;
                        break;
                    }
                }
            }

            // ------------------------------------------------------------
            // F. YEAR EXTRACTION
            // ------------------------------------------------------------

            const yearMatch = fullText.match(/\b(20\d{2})\b/);
            year = yearMatch ? yearMatch[1] : new Date().getFullYear().toString();

            // ------------------------------------------------------------
            // G. GPA / GRADE / SCORE EXTRACTION (if applicable)
            // ------------------------------------------------------------

            const gpaPatterns = [
                /CGPA\s*[:\=]?\s*(\d+(?:\.\d+)?(?:\s*\/\s*10)?)/i,
                /GPA\s*[:\=]?\s*(\d+(?:\.\d+)?(?:\s*\/\s*4)?)/i,
                /Grade\s*[:\=]?\s*([A-O\+\-]+)/i,
                /Percentage\s*[:\=]?\s*(\d+(?:\.\d+)?\%)/i,
                /(First\s+Class(?:\s+with\s+Distinction)?|Distinction)/i
            ];

            for (const pat of gpaPatterns) {
                const match = fullText.match(pat);
                if (match && match[1]) {
                    gpa = cleanString(match[1]);
                    break;
                }
            }

            // ============================================================
            // 6. RESULT PACKAGING & SUMMARY
            // ============================================================
            const result = {
                name: name || "",
                registerNumber: registerNumber || "",
                institution: institution || "",
                organizer: organizer || "",
                degree: degree || "",
                year: year,
                gpa: gpa || ""
            };

            console.log("[OCR] Final Extracted Fields:", result);

            if (!name && !degree && !institution) {
                alert("OCR finished, but could not automatically detect details with high confidence. Please verify or manually enter details in the form.");
            }

            return result;

        } catch (err) {
            console.error("[OCR] Extraction Error:", err);
            alert("OCR Failed: " + (err.message || "Unknown Error") + "\n\nPlease manually enter the correct details in the form.");
            return { name: "", registerNumber: "", institution: "", organizer: "", degree: "", year: new Date().getFullYear().toString(), gpa: "" };
        }
    }
};


// ==========================================
// CERTIFICATE COMPARISON MODULE
// ==========================================

const CertificateComparator = {
    /**
     * Normalize person recipient name (collapses titles, standardizes spaces/initials)
     * e.g. "Akshay Anand M.P." -> "AKSHAY ANAND M P"
     */
    normalizeName: (name) => {
        if (!name) return "";
        return name
            .toString()
            .toUpperCase()
            .replace(/^(?:MR\.?|MS\.?|MRS\.?|MISS\.?|DR\.?|PROF\.?|SHRI\.?|SMT\.?|MX\.?|MASTER)\s+/i, '')
            .replace(/^(?:MR\.?\s*\/\s*MS\.?|MS\.?\s*\/\s*MR\.?)\s+/i, '')
            .replace(/[\.\,\;\:\'\"\_]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    },

    /**
     * Normalize Certificate ID / Register Number strictly
     * e.g. "CERT - 2026 / 001" -> "CERT-2026/001"
     */
    normalizeCertificateId: (id) => {
        if (!id) return "";
        return id
            .toString()
            .toUpperCase()
            .replace(/\s+/g, '')
            .replace(/[\:\#]/g, '')
            .trim();
    },

    /**
     * Normalize Institution name
     * e.g. "Dr. N.G.P. Institute of Technology" -> "DR NGP INSTITUTE OF TECHNOLOGY"
     */
    normalizeInstitution: (inst) => {
        if (!inst) return "";
        return inst
            .toString()
            .toUpperCase()
            .replace(/^(?:OF|FROM|AT|STUDENT OF)\s+/i, '')
            .replace(/[\.\,\;\:\'\"\_\-\(\)]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    },

    /**
     * Normalize Course / Degree name
     */
    normalizeCourse: (course) => {
        if (!course) return "";
        return course
            .toString()
            .toUpperCase()
            .replace(/[\.\,\;\:\'\"\_\-\(\)]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    },

    /**
     * Normalize Date format
     */
    normalizeDate: (date) => {
        if (!date) return "";
        const str = date.toString().trim();
        const dMatch = str.match(/(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{2,4})/);
        if (dMatch) {
            const day = dMatch[1].padStart(2, '0');
            const month = dMatch[2].padStart(2, '0');
            const yr = dMatch[3].length === 2 ? '20' + dMatch[3] : dMatch[3];
            return `${day}-${month}-${yr}`;
        }
        const yMatch = str.match(/\b(20\d{2}|19\d{2})\b/);
        if (yMatch) return yMatch[1];
        return str.toUpperCase().replace(/\s+/g, ' ');
    },

    /**
     * Generate canonical deterministic representation for hashing / comparison
     */
    generateCanonicalData: (cert) => {
        const name = CertificateComparator.normalizeName(cert.name || cert.studentName || cert.recipientName || "");
        const certId = CertificateComparator.normalizeCertificateId(cert.certificateId || cert.registerNumber || cert.certificateNumber || "");
        const institution = CertificateComparator.normalizeInstitution(cert.institution || cert.institutionName || cert.organizer || "");
        const course = CertificateComparator.normalizeCourse(cert.course || cert.degree || cert.verifiedCertificateName || "");
        const date = CertificateComparator.normalizeDate(cert.date || cert.year || cert.issuedAt || "");

        return `NAME=${name}\nCERTIFICATE_ID=${certId}\nINSTITUTION=${institution}\nCOURSE=${course}\nDATE=${date}`;
    },

    /**
     * Calculate Levenshtein distance between two strings
     * @param {string} str1 - First string
     * @param {string} str2 - Second string
     * @returns {number} Edit distance between strings
     */
    levenshteinDistance: (str1, str2) => {
        const m = str1.length;
        const n = str2.length;

        // Create a 2D array to store distances
        const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

        // Initialize base cases
        for (let i = 0; i <= m; i++) dp[i][0] = i;
        for (let j = 0; j <= n; j++) dp[0][j] = j;

        // Fill the matrix
        for (let i = 1; i <= m; i++) {
            for (let j = 1; j <= n; j++) {
                if (str1[i - 1] === str2[j - 1]) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    dp[i][j] = 1 + Math.min(
                        dp[i - 1][j],     // deletion
                        dp[i][j - 1],     // insertion
                        dp[i - 1][j - 1]  // substitution
                    );
                }
            }
        }

        return dp[m][n];
    },

    /**
     * Calculate similarity percentage between two strings
     * @param {string} str1 - First string
     * @param {string} str2 - Second string
     * @returns {number} Similarity percentage (0-100)
     */
    calculateSimilarity: (str1, str2) => {
        if (!str1 && !str2) return 100;
        if (!str1 || !str2) return 0;

        const maxLen = Math.max(str1.length, str2.length);
        if (maxLen === 0) return 100;

        const distance = CertificateComparator.levenshteinDistance(str1, str2);
        return ((maxLen - distance) / maxLen) * 100;
    },

    /**
     * Check if two strings are similar enough (fuzzy match)
     * CRITICAL FIX: Empty string is NEVER treated as a match!
     * @param {string} str1 - First string
     * @param {string} str2 - Second string
     * @param {string} fieldType - Type of field being compared ('number', 'name', 'institution')
     * @returns {boolean} True if strings are similar enough
     */
    isFuzzyMatch: (str1, str2, fieldType = 'default') => {
        // If either is missing/empty, it cannot match!
        if (!str1 || !str2 || str1.toString().trim() === "" || str2.toString().trim() === "") {
            console.log(`[CertificateComparator] Field "${fieldType}" empty or missing - match failed`);
            return false;
        }

        const s1 = str1.toString().trim();
        const s2 = str2.toString().trim();

        // Exact match
        if (s1 === s2) return true;

        // 1. Strict Certificate ID matching (e.g. CERT-2026-001 vs CERT-2026-999 must NOT match)
        if (fieldType === 'number' || fieldType === 'certificate_number' || fieldType === 'certificateId') {
            const id1 = CertificateComparator.normalizeCertificateId(s1);
            const id2 = CertificateComparator.normalizeCertificateId(s2);
            if (id1 === id2) return true;

            const dist = CertificateComparator.levenshteinDistance(id1, id2);
            const maxLen = Math.max(id1.length, id2.length);
            const sim = maxLen === 0 ? 100 : ((maxLen - dist) / maxLen) * 100;

            // Strict: require >= 92% similarity and at most 1 char difference for minor single-glyph OCR error
            const isMatch = sim >= 92 && dist <= 1;
            console.log(`[CertificateComparator] Strict ID match: "${id1}" vs "${id2}" -> ${isMatch}`);
            return isMatch;
        }

        // 2. Person Name matching (tolerates minor spacing, initials and formatting)
        if (fieldType === 'name' || fieldType === 'verified_certificate_name') {
            const name1 = CertificateComparator.normalizeName(s1);
            const name2 = CertificateComparator.normalizeName(s2);
            if (name1 === name2) return true;

            const stripped1 = name1.replace(/\s/g, '');
            const stripped2 = name2.replace(/\s/g, '');
            if (stripped1 === stripped2) return true;

            const nameDist = CertificateComparator.levenshteinDistance(stripped1, stripped2);
            const nameMaxLen = Math.max(stripped1.length, stripped2.length);
            const nameSim = nameMaxLen === 0 ? 100 : ((nameMaxLen - nameDist) / nameMaxLen) * 100;

            const isMatch = nameSim >= 78;
            console.log(`[CertificateComparator] Name match: "${name1}" vs "${name2}" -> ${isMatch} (${nameSim.toFixed(1)}%)`);
            return isMatch;
        }

        // 3. Institution / Course / Other fields
        const norm1 = CertificateComparator.normalizeInstitution(s1);
        const norm2 = CertificateComparator.normalizeInstitution(s2);
        if (norm1 === norm2) return true;

        const distance = CertificateComparator.levenshteinDistance(norm1, norm2);
        const maxLen = Math.max(norm1.length, norm2.length);
        const similarity = maxLen === 0 ? 100 : ((maxLen - distance) / maxLen) * 100;

        const isMatch = similarity >= 75;
        console.log(`[CertificateComparator] Field "${fieldType}" match: ${isMatch} (${similarity.toFixed(1)}%)`);
        return isMatch;
    },

    /**
     * Extract comparison-relevant fields from OCR data or certificate object
     * @param {Object} certData - Certificate data (from OCR or database)
     * @returns {Object} Normalized certificate fields for comparison
     */
    extractFields: (certData) => {
        return {
            certificateNumber: CertificateComparator.normalizeCertificateId(
                certData.registerNumber || certData.certificateNumber || certData.certificateId || certData.certNo || ""
            ),
            institutionName: CertificateComparator.normalizeInstitution(
                certData.institution || certData.institutionName || certData.organizer || ""
            ),
            verifiedCertificateName: CertificateComparator.normalizeName(
                certData.name || certData.studentName || certData.degree || certData.certificateName || ""
            )
        };
    },

    /**
     * Normalize a field for comparison (trim, lowercase, remove extra spaces)
     * @param {string} value - The field value to normalize
     * @returns {string} Normalized value
     */
    normalizeField: (value) => {
        if (!value) return "";
        return value
            .toString()
            .trim()
            .toLowerCase()
            .replace(/\s+/g, ' ')
            .replace(/[.,\-_:;'"()[\]{}]/g, '')  // Remove more punctuation
            .replace(/\s/g, '');
    },

    /**
     * Compare a single field between two values with fuzzy matching
     * @param {string} field1 - First certificate field value
     * @param {string} field2 - Second certificate field value
     * @param {string} fieldName - Display name of the field
     * @returns {Object} Comparison result for this field
     */
    compareField: (field1, field2, fieldName) => {
        const normalized1 = CertificateComparator.normalizeField(field1);
        const normalized2 = CertificateComparator.normalizeField(field2);

        // Determine field type for matching rules
        let fieldType = 'default';
        if (fieldName.toLowerCase().includes('number') || fieldName.toLowerCase().includes('certificate')) {
            fieldType = 'certificate_number';
        } else if (fieldName.toLowerCase().includes('institution')) {
            fieldType = 'institution';
        } else if (fieldName.toLowerCase().includes('name')) {
            fieldType = 'name';
        }

        // Use fuzzy matching to handle OCR inaccuracies
        const isMatch = CertificateComparator.isFuzzyMatch(normalized1, normalized2, fieldType);
        const isEmpty1 = normalized1.length === 0;
        const isEmpty2 = normalized2.length === 0;

        let status = "Match";
        let message = `${fieldName}: ✓ Match`;

        if (isEmpty1 && isEmpty2) {
            status = "Empty";
            message = `${fieldName}: ⚠ Both fields are empty`;
        } else if (isEmpty1 || isEmpty2) {
            status = "Missing";
            message = `${fieldName}: ⚠ One field is missing data`;
        } else if (!isMatch) {
            status = "Mismatch";
            message = `${fieldName}: ✗ Mismatch`;
        }

        return {
            fieldName,
            originalValue: field1,
            newValue: field2,
            isMatch,
            status,
            message
        };
    },

    /**
     * Compare two certificates and return detailed results
     * @param {Object} previousCert - Previously uploaded certificate data
     * @param {Object} newCert - Newly uploaded certificate data
     * @returns {Object} Comprehensive comparison results
     */
    compare: (previousCert, newCert) => {
        console.log("[CertificateComparator] Comparing certificates...");
        console.log("[CertificateComparator] Previous:", previousCert);
        console.log("[CertificateComparator] New:", newCert);

        // Extract fields from both certificates
        const prevFields = CertificateComparator.extractFields(previousCert);
        const newFields = CertificateComparator.extractFields(newCert);

        // Prepare results object
        const results = {
            success: true,
            overallMatch: true,
            timestamp: new Date().toISOString(),
            summary: "",
            fields: {
                certificateNumber: null,
                institutionName: null,
                verifiedCertificateName: null
            },
            errors: []
        };

        // Step 1: Compare Certificate Numbers
        const certNumResult = CertificateComparator.compareField(
            previousCert.registerNumber || previousCert.certificateNumber || "",
            newCert.registerNumber || newCert.certificateNumber || "",
            "Certificate Number"
        );
        results.fields.certificateNumber = certNumResult;

        if (certNumResult.status === "Mismatch") {
            results.overallMatch = false;
            results.summary = "Certificate numbers do not match.";
            results.errors.push({
                field: "Certificate Number",
                message: "Certificate numbers do not match.",
                previous: certNumResult.originalValue,
                new: certNumResult.newValue
            });

            // Per requirements: Return immediately on certificate number mismatch
            results.fields.institutionName = {
                fieldName: "Institution Name",
                status: "Skipped",
                message: "Institution Name: ⏸ Comparison skipped (Certificate Number mismatch)"
            };
            results.fields.verifiedCertificateName = {
                fieldName: "Verified Certificate Name",
                status: "Skipped",
                message: "Verified Certificate Name: ⏸ Comparison skipped (Certificate Number mismatch)"
            };

            return results;
        }

        // Step 2: Compare Institution Names (only if certificate numbers match)
        const instResult = CertificateComparator.compareField(
            previousCert.institution || previousCert.institutionName || previousCert.organizer || "",
            newCert.institution || newCert.institutionName || newCert.organizer || "",
            "Institution Name"
        );
        results.fields.institutionName = instResult;

        if (instResult.status === "Mismatch") {
            results.overallMatch = false;
            results.summary = "Institution names do not match.";
            results.errors.push({
                field: "Institution Name",
                message: "Institution names do not match.",
                previous: instResult.originalValue,
                new: instResult.newValue
            });

            // Per requirements: Return immediately on institution name mismatch
            results.fields.verifiedCertificateName = {
                fieldName: "Verified Certificate Name",
                status: "Skipped",
                message: "Verified Certificate Name: ⏸ Comparison skipped (Institution Name mismatch)"
            };

            return results;
        }

        // Step 3: Compare Verified Certificate Names (only if both above match)
        const certNameResult = CertificateComparator.compareField(
            previousCert.degree || previousCert.certificateName || previousCert.name || "",
            newCert.degree || newCert.certificateName || newCert.name || "",
            "Verified Certificate Name"
        );
        results.fields.verifiedCertificateName = certNameResult;

        if (certNameResult.status === "Mismatch") {
            results.overallMatch = false;
            results.summary = "Verified certificate names are mismatched.";
            results.errors.push({
                field: "Verified Certificate Name",
                message: "Verified certificate names are mismatched.",
                previous: certNameResult.originalValue,
                new: certNameResult.newValue
            });

            return results;
        }

        // All fields match!
        results.summary = "Certificates are verified and match.";

        return results;
    },

    /**
     * Generate a formatted text report of comparison results
     * @param {Object} results - Comparison results from compare()
     * @returns {string} Formatted text report
     */
    generateReport: (results) => {
        let report = "╔══════════════════════════════════════════════════════════╗\n";
        report += "║           CERTIFICATE COMPARISON RESULTS                 ║\n";
        report += "╠══════════════════════════════════════════════════════════╣\n";

        // Certificate Number
        const certNum = results.fields.certificateNumber;
        report += `║ • Certificate Number: ${certNum.status.padEnd(15)} `;
        if (certNum.status === "Match") {
            report += "✓ MATCH".padEnd(20) + "║\n";
        } else if (certNum.status === "Mismatch") {
            report += "✗ MISMATCH".padEnd(20) + "║\n";
            report += `║   Previous: ${(certNum.originalValue || "N/A").substring(0, 40).padEnd(42)}║\n`;
            report += `║   New:      ${(certNum.newValue || "N/A").substring(0, 40).padEnd(42)}║\n`;
        } else {
            report += (certNum.status || "N/A").padEnd(20) + "║\n";
        }

        // Institution Name
        const instName = results.fields.institutionName;
        if (instName) {
            report += `║ • Institution Name: ${(instName.status || "").padEnd(17)} `;
            if (instName.status === "Match") {
                report += "✓ MATCH".padEnd(20) + "║\n";
            } else if (instName.status === "Mismatch") {
                report += "✗ MISMATCH".padEnd(20) + "║\n";
                report += `║   Previous: ${(instName.originalValue || "N/A").substring(0, 40).padEnd(42)}║\n`;
                report += `║   New:      ${(instName.newValue || "N/A").substring(0, 40).padEnd(42)}║\n`;
            } else {
                report += (instName.status || "SKIPPED").padEnd(20) + "║\n";
            }
        }

        // Verified Certificate Name
        const certName = results.fields.verifiedCertificateName;
        if (certName) {
            report += `║ • Verified Certificate Name: ${(certName.status || "").padEnd(8)} `;
            if (certName.status === "Match") {
                report += "✓ MATCH".padEnd(20) + "║\n";
            } else if (certName.status === "Mismatch") {
                report += "✗ MISMATCH".padEnd(20) + "║\n";
                report += `║   Previous: ${(certName.originalValue || "N/A").substring(0, 40).padEnd(42)}║\n`;
                report += `║   New:      ${(certName.newValue || "N/A").substring(0, 40).padEnd(42)}║\n`;
            } else {
                report += (certName.status || "SKIPPED").padEnd(20) + "║\n";
            }
        }

        report += "╠══════════════════════════════════════════════════════════╣\n";

        // Overall Summary
        if (results.overallMatch) {
            report += "║ ✓ OVERALL RESULT: CERTIFICATES VERIFIED AND MATCH       ║\n";
        } else {
            report += "║ ✗ OVERALL RESULT: DISCREPANCY DETECTED                  ║\n";
            report += `║   ${results.summary.padEnd(54)}║\n`;
        }

        report += "╚══════════════════════════════════════════════════════════╝\n";

        return report;
    },

    /**
     * Generate HTML formatted comparison results for UI display
     * @param {Object} results - Comparison results from compare()
     * @returns {string} HTML formatted results
     */
    generateHTML: (results) => {
        const getStatusIcon = (status) => {
            switch (status) {
                case "Match": return '<i class="bx bx-check-circle" style="color: var(--success);"></i>';
                case "Mismatch": return '<i class="bx bx-x-circle" style="color: var(--danger);"></i>';
                case "Skipped": return '<i class="bx bx-pause-circle" style="color: var(--warning);"></i>';
                case "Empty": return '<i class="bx bx-error-circle" style="color: var(--warning);"></i>';
                case "Missing": return '<i class="bx bx-error-circle" style="color: var(--warning);"></i>';
                default: return '<i class="bx bx-question-mark"></i>';
            }
        };

        const getStatusClass = (status) => {
            switch (status) {
                case "Match": return "status-success";
                case "Mismatch": return "status-danger";
                default: return "status-warning";
            }
        };

        let html = `
        <div class="comparison-results glass-card" style="padding: 1.5rem; margin-top: 1rem;">
            <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                <i class='bx bx-git-compare' style="color: var(--primary);"></i>
                Certificate Comparison Results
            </h3>
            
            <div class="comparison-fields" style="display: flex; flex-direction: column; gap: 1rem;">
        `;

        // Certificate Number
        const certNum = results.fields.certificateNumber;
        html += `
            <div class="comparison-field ${getStatusClass(certNum.status)}" style="padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; border-left: 3px solid ${certNum.status === 'Match' ? 'var(--success)' : certNum.status === 'Mismatch' ? 'var(--danger)' : 'var(--warning)'};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 600;">Certificate Number</span>
                    <span>${getStatusIcon(certNum.status)} ${certNum.status}</span>
                </div>
                ${certNum.status === 'Mismatch' ? `
                    <div style="margin-top: 0.5rem; font-size: 0.85rem; color: var(--text-muted);">
                        <div>Previous: <code>${certNum.originalValue || 'N/A'}</code></div>
                        <div>New: <code>${certNum.newValue || 'N/A'}</code></div>
                    </div>
                ` : ''}
            </div>
        `;

        // Institution Name
        const instName = results.fields.institutionName;
        if (instName) {
            html += `
                <div class="comparison-field ${getStatusClass(instName.status)}" style="padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; border-left: 3px solid ${instName.status === 'Match' ? 'var(--success)' : instName.status === 'Mismatch' ? 'var(--danger)' : 'var(--warning)'};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 600;">Institution Name</span>
                        <span>${getStatusIcon(instName.status)} ${instName.status}</span>
                    </div>
                    ${instName.status === 'Mismatch' ? `
                        <div style="margin-top: 0.5rem; font-size: 0.85rem; color: var(--text-muted);">
                            <div>Previous: <code>${instName.originalValue || 'N/A'}</code></div>
                            <div>New: <code>${instName.newValue || 'N/A'}</code></div>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // Verified Certificate Name
        const certName = results.fields.verifiedCertificateName;
        if (certName) {
            html += `
                <div class="comparison-field ${getStatusClass(certName.status)}" style="padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; border-left: 3px solid ${certName.status === 'Match' ? 'var(--success)' : certName.status === 'Mismatch' ? 'var(--danger)' : 'var(--warning)'};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 600;">Verified Certificate Name</span>
                        <span>${getStatusIcon(certName.status)} ${certName.status}</span>
                    </div>
                    ${certName.status === 'Mismatch' ? `
                        <div style="margin-top: 0.5rem; font-size: 0.85rem; color: var(--text-muted);">
                            <div>Previous: <code>${certName.originalValue || 'N/A'}</code></div>
                            <div>New: <code>${certName.newValue || 'N/A'}</code></div>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // Overall Summary
        html += `
            </div>
            
            <div class="comparison-summary" style="margin-top: 1.5rem; padding: 1rem; border-radius: 8px; background: ${results.overallMatch ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)'}; border: 1px solid ${results.overallMatch ? 'var(--success)' : 'var(--danger)'};">
                <div style="display: flex; align-items: center; gap: 0.5rem; font-weight: 600;">
                    ${results.overallMatch
                ? '<i class="bx bx-check-shield" style="font-size: 1.5rem; color: var(--success);"></i>'
                : '<i class="bx bx-shield-x" style="font-size: 1.5rem; color: var(--danger);"></i>'
            }
                    <span>${results.summary}</span>
                </div>
            </div>
        </div>
        `;

        return html;
    },

    /**
     * Compare two certificate images using OCR extraction first
     * @param {string} previousImage - Base64 encoded previous certificate image
     * @param {string} newImage - Base64 encoded new certificate image
     * @returns {Promise<Object>} Comparison results
     */
    compareImages: async (previousImage, newImage) => {
        try {
            console.log("[CertificateComparator] Extracting data from previous certificate...");
            const prevData = await API.ocrExtract(previousImage);

            console.log("[CertificateComparator] Extracting data from new certificate...");
            const newData = await API.ocrExtract(newImage);

            return CertificateComparator.compare(prevData, newData);
        } catch (error) {
            console.error("[CertificateComparator] OCR Comparison Error:", error);
            return {
                success: false,
                overallMatch: false,
                summary: "Error during OCR extraction: " + error.message,
                fields: {
                    certificateNumber: { status: "Error", message: error.message },
                    institutionName: { status: "Error", message: error.message },
                    verifiedCertificateName: { status: "Error", message: error.message }
                },
                errors: [{ field: "OCR", message: error.message }]
            };
        }
    }
};

// Make CertificateComparator globally accessible
window.CertificateComparator = CertificateComparator;


// ==========================================
// CERTIFICATE VERIFIER MODULE (Two-Layer Verification)
// ==========================================

const CertificateVerifier = {
    /**
     * Purpose: Certificate integrity and authenticity verification
     * Description: Analyze and compare uploaded certificates to detect forgery 
     * or tampering using hash verification and OCR-based field comparison.
     */

    /**
     * Generate SHA-256 hash from file binary (base64 or ArrayBuffer)
     * @param {string|ArrayBuffer} fileData - Base64 string or ArrayBuffer of file
     * @returns {Promise<string>} SHA-256 hash as hex string
     */
    generateHash: async (fileData) => {
        try {
            let arrayBuffer;

            if (typeof fileData === 'string') {
                // Handle base64 string
                let base64 = fileData;
                if (fileData.includes(',')) {
                    base64 = fileData.split(',')[1];
                }

                // Decode base64 to binary
                const binaryString = atob(base64);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                arrayBuffer = bytes.buffer;
            } else if (fileData instanceof ArrayBuffer) {
                arrayBuffer = fileData;
            } else if (fileData instanceof Blob) {
                arrayBuffer = await fileData.arrayBuffer();
            } else {
                throw new Error("Invalid file data format");
            }

            // Generate SHA-256 hash using Web Crypto API
            const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);

            // Convert to hex string
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            console.log("[CertificateVerifier] Generated SHA-256 hash:", hashHex);
            return hashHex;

        } catch (error) {
            console.error("[CertificateVerifier] Hash generation error:", error);
            throw new Error("Failed to generate file hash: " + error.message);
        }
    },

    /**
     * Layer 1: Hash Verification
     * Compare uploaded file hash with stored original hash
     * @param {string} originalHash - Stored SHA-256 hash of original certificate
     * @param {string} uploadedHash - Generated SHA-256 hash of uploaded certificate
     * @returns {Object} Hash verification result
     */
    verifyHash: (originalHash, uploadedHash) => {
        const normalizedOriginal = (originalHash || "").toLowerCase().trim();
        const normalizedUploaded = (uploadedHash || "").toLowerCase().trim();

        const isMatch = normalizedOriginal === normalizedUploaded;

        return {
            status: isMatch ? "Matched" : "Mismatched",
            isMatch,
            originalHash: normalizedOriginal,
            uploadedHash: normalizedUploaded,
            message: isMatch
                ? "Hash verification passed - File integrity confirmed"
                : "Hash verification failed - Certificate content has been modified"
        };
    },

    /**
     * Layer 2: OCR Field Comparison
     * Extract and compare certificate fields
     * @param {Object} originalData - Original certificate data from database
     * @param {Object} extractedData - OCR extracted data from uploaded certificate
     * @returns {Object} Field comparison results
     */
    compareFields: (originalData, extractedData) => {
        console.log("[CertificateVerifier] Original data:", originalData);
        console.log("[CertificateVerifier] Extracted data:", extractedData);

        const fields = {
            certificate_number: {
                original: originalData.certificateNumber || originalData.registerNumber || originalData.certificate_number || originalData.certificateId || "",
                extracted: extractedData.certificateNumber || extractedData.registerNumber || extractedData.certificate_number || extractedData.certificateId || "",
                status: "Pending"
            },
            institution_name: {
                original: originalData.institutionName || originalData.institution || originalData.institution_name || "",
                extracted: extractedData.institutionName || extractedData.institution || extractedData.institution_name || "",
                status: "Pending"
            },
            verified_certificate_name: {
                original: originalData.name || originalData.recipientName || originalData.verifiedCertificateName || originalData.studentName || "",
                extracted: extractedData.name || extractedData.recipientName || extractedData.verifiedCertificateName || "",
                status: "Pending"
            }
        };

        let editedFields = [];
        let missingFields = [];
        let comparisonDetails = [];

        const comparisonOrder = ["certificate_number", "institution_name", "verified_certificate_name"];

        for (const fieldName of comparisonOrder) {
            const field = fields[fieldName];
            const orig = field.original || "";
            const extr = field.extracted || "";

            if (!extr || extr.trim() === "") {
                field.status = "Missing";
                missingFields.push(fieldName);
                editedFields.push(fieldName);
                comparisonDetails.push({ field: fieldName, original: orig, extracted: extr, isMatch: false, status: "Missing" });
                continue;
            }

            const isMatch = CertificateComparator.isFuzzyMatch(orig, extr, fieldName);
            comparisonDetails.push({ field: fieldName, original: orig, extracted: extr, isMatch, status: isMatch ? "Match" : "Mismatch" });

            if (!isMatch) {
                field.status = "Mismatch";
                editedFields.push(fieldName);
            } else {
                field.status = "Match";
            }
        }

        // If key information (both name & ID) could not be extracted by OCR -> UNABLE TO VERIFY
        const hasKeyExtraction = Boolean(fields.verified_certificate_name.extracted && fields.verified_certificate_name.extracted.length > 1) ||
                                 Boolean(fields.certificate_number.extracted && fields.certificate_number.extracted.length > 1);
        const unableToVerify = !hasKeyExtraction || (missingFields.length >= 2);

        return {
            fields,
            editedFields,
            missingFields,
            unableToVerify,
            comparisonDetails,
            allMatch: editedFields.length === 0 && !unableToVerify,
            message: unableToVerify
                ? "UNABLE TO VERIFY: Required certificate information could not be reliably extracted"
                : (editedFields.length === 0 ? "All fields match - Certificate is authentic" : `Fields mismatched: ${editedFields.join(", ")}`)
        };
    },

    /**
     * Full Certificate Verification Process
     * Implements both Layer 1 (Hash) and Layer 2 (OCR) verification
     * @param {Object} originalCertificate - Original certificate data with hash
     * @param {Object} uploadedCertificate - Uploaded certificate with file binary
     * @returns {Promise<Object>} Complete verification report
     */
    verify: async (originalCertificate, uploadedCertificate) => {
        console.log("[CertificateVerifier] Starting full verification process...");

        const report = {
            timestamp: new Date().toISOString(),
            certificate_verification_report: {
                hash_verification: {
                    status: "Pending",
                    original_hash: "",
                    uploaded_hash: "",
                    message: ""
                },
                field_comparison: {
                    certificate_number: "Pending",
                    institution_name: "Pending",
                    verified_certificate_name: "Pending"
                },
                final_result: "PENDING",
                remarks: ""
            }
        };

        try {
            // =============================================
            // LAYER 1: HASH VERIFICATION
            // =============================================
            console.log("[CertificateVerifier] Layer 1: Hash Verification...");

            // Generate hash from uploaded file
            const uploadedHash = await CertificateVerifier.generateHash(
                uploadedCertificate.file_binary || uploadedCertificate.fileBinary || uploadedCertificate.base64
            );

            // Get original hash from stored certificate
            const originalHash = originalCertificate.file_hash_sha256 ||
                originalCertificate.fileHash ||
                originalCertificate.hash || "";

            // Compare hashes
            const hashResult = CertificateVerifier.verifyHash(originalHash, uploadedHash);

            report.certificate_verification_report.hash_verification = {
                status: hashResult.status,
                original_hash: hashResult.originalHash,
                uploaded_hash: hashResult.uploadedHash,
                message: hashResult.message
            };

            // DECISION: If hash mismatch, certificate is FAKE
            if (!hashResult.isMatch) {
                report.certificate_verification_report.final_result = "FAKE";
                report.certificate_verification_report.remarks =
                    "❌ FAKE CERTIFICATE DETECTED: The file content has been modified. " +
                    "The SHA-256 hash of the uploaded certificate does not match the original stored hash. " +
                    "This indicates the certificate file has been tampered with or replaced.";

                // Mark all field comparisons as N/A
                report.certificate_verification_report.field_comparison = {
                    certificate_number: "N/A (Hash Mismatch)",
                    institution_name: "N/A (Hash Mismatch)",
                    verified_certificate_name: "N/A (Hash Mismatch)"
                };

                console.log("[CertificateVerifier] RESULT: FAKE - Hash mismatch detected");
                return report;
            }

            // =============================================
            // LAYER 2: OCR FIELD COMPARISON
            // =============================================
            console.log("[CertificateVerifier] Layer 2: OCR Field Comparison...");

            // Extract text from uploaded certificate using OCR if not already provided
            let extractedData = uploadedCertificate.ocr_extracted_data || uploadedCertificate.ocrData;

            if (!extractedData && (uploadedCertificate.file_binary || uploadedCertificate.base64)) {
                console.log("[CertificateVerifier] Running OCR extraction on uploaded certificate...");
                extractedData = await API.ocrExtract(
                    uploadedCertificate.file_binary || uploadedCertificate.base64
                );
            }

            // Prepare original data for comparison
            const originalData = {
                certificateNumber: originalCertificate.certificate_number || originalCertificate.certificateNumber || originalCertificate.registerNumber || "",
                institutionName: originalCertificate.institution_name || originalCertificate.institutionName || originalCertificate.institution || "",
                verifiedCertificateName: originalCertificate.verified_certificate_name || originalCertificate.verifiedCertificateName || originalCertificate.degree || "",
                name: originalCertificate.name || originalCertificate.studentName || originalCertificate.recipientName || originalCertificate.verifiedCertificateName || originalCertificate.verified_certificate_name || ""
            };

            // Compare fields
            const fieldResult = CertificateVerifier.compareFields(originalData, extractedData);

            report.certificate_verification_report.field_comparison = {
                certificate_number: fieldResult.fields.certificate_number.status,
                institution_name: fieldResult.fields.institution_name.status,
                verified_certificate_name: fieldResult.fields.verified_certificate_name.status
            };

            // DECISION: Determine final result
            if (fieldResult.unableToVerify) {
                report.certificate_verification_report.final_result = "UNABLE TO VERIFY";
                report.certificate_verification_report.remarks =
                    "⚠️ UNABLE TO VERIFY: Required certificate details (Name or Certificate ID) could not be reliably extracted from the uploaded document. Please upload a clearer scan.";
                console.log("[CertificateVerifier] RESULT: UNABLE TO VERIFY - Missing key fields");
            } else if (fieldResult.allMatch) {
                // Hash match + All fields match = VALID
                report.certificate_verification_report.final_result = "VALID";
                report.certificate_verification_report.remarks =
                    "✅ VALID CERTIFICATE: The certificate has been verified successfully. " +
                    "The file hash matches the original, and all extracted fields " +
                    "(Certificate Number, Institution Name, Verified Certificate Name) " +
                    "match the stored records. This certificate is authentic.";

                console.log("[CertificateVerifier] RESULT: VALID - All checks passed");
            } else {
                const isAllMismatch = fieldResult.editedFields.length >= 2;
                report.certificate_verification_report.final_result = isAllMismatch ? "FAKE" : "EDITED";
                report.certificate_verification_report.remarks =
                    `❌ ${isAllMismatch ? "FAKE" : "EDITED"} CERTIFICATE DETECTED: The following field(s) do not match: ${fieldResult.editedFields.join(", ")}.`;
                console.log("[CertificateVerifier] RESULT: " + report.certificate_verification_report.final_result);
            }

            return report;

        } catch (error) {
            console.error("[CertificateVerifier] Verification error:", error);

            report.certificate_verification_report.final_result = "ERROR";
            report.certificate_verification_report.remarks =
                `❌ VERIFICATION ERROR: ${error.message}. Please try again or contact support.`;

            return report;
        }
    },

    /**
     * Quick verification using only OCR (without hash - for legacy certificates)
     * @param {Object} originalCertificate - Original certificate data
     * @param {string} uploadedImageBase64 - Base64 encoded uploaded certificate image
     * @returns {Promise<Object>} Verification report
     */
    verifyWithoutHash: async (originalCertificate, uploadedImageBase64) => {
        console.log("[CertificateVerifier] Starting OCR-only verification (no hash)...");

        const report = {
            timestamp: new Date().toISOString(),
            certificate_verification_report: {
                hash_verification: {
                    status: "Skipped",
                    message: "Hash verification skipped - original hash not available"
                },
                field_comparison: {
                    certificate_number: "Pending",
                    institution_name: "Pending",
                    verified_certificate_name: "Pending"
                },
                final_result: "PENDING",
                remarks: ""
            }
        };

        try {
            // Extract text using OCR
            const extractedData = await API.ocrExtract(uploadedImageBase64);

            // Prepare original data
            const originalData = {
                certificateNumber: originalCertificate.certificate_number || originalCertificate.certificateNumber || originalCertificate.registerNumber || "",
                institutionName: originalCertificate.institution_name || originalCertificate.institutionName || originalCertificate.institution || "",
                verifiedCertificateName: originalCertificate.verified_certificate_name || originalCertificate.verifiedCertificateName || originalCertificate.degree || "",
                name: originalCertificate.name || originalCertificate.studentName || originalCertificate.recipientName || originalCertificate.verifiedCertificateName || originalCertificate.verified_certificate_name || ""
            };

            // Compare fields
            const fieldResult = CertificateVerifier.compareFields(originalData, extractedData);

            report.certificate_verification_report.field_comparison = {
                certificate_number: fieldResult.fields.certificate_number.status,
                institution_name: fieldResult.fields.institution_name.status,
                verified_certificate_name: fieldResult.fields.verified_certificate_name.status
            };

            if (fieldResult.unableToVerify) {
                report.certificate_verification_report.final_result = "UNABLE TO VERIFY";
                report.certificate_verification_report.remarks =
                    "⚠️ UNABLE TO VERIFY: Required certificate details could not be reliably extracted from the uploaded document.";
            } else if (fieldResult.allMatch) {
                report.certificate_verification_report.final_result = "VALID";
                report.certificate_verification_report.remarks =
                    "✅ CERTIFICATE FIELDS VERIFIED: All extracted fields match the stored records. (Note: File hash verification was skipped).";
            } else {
                const allFieldsMismatch = fieldResult.editedFields.length >= 2;
                report.certificate_verification_report.final_result = allFieldsMismatch ? "FAKE" : "EDITED";
                report.certificate_verification_report.remarks =
                    `❌ ${allFieldsMismatch ? "FAKE" : "EDITED"} CERTIFICATE DETECTED: The following field(s) do not match: ${fieldResult.editedFields.join(", ")}.`;
            }

            return report;

        } catch (error) {
            console.error("[CertificateVerifier] OCR verification error:", error);
            report.certificate_verification_report.final_result = "ERROR";
            report.certificate_verification_report.remarks = `❌ Error: ${error.message}`;
            return report;
        }
    },

    /**
     * Generate HTML report for UI display
     * @param {Object} report - Verification report from verify()
     * @returns {string} HTML formatted report
     */
    generateHTMLReport: (report) => {
        const vr = report.certificate_verification_report;

        const getResultColor = (result) => {
            switch (result) {
                case "VALID": return "var(--success)";
                case "EDITED": return "var(--warning)";
                case "UNABLE TO VERIFY": return "var(--warning)";
                case "FAKE": return "var(--danger)";
                default: return "var(--text-muted)";
            }
        };

        const getResultIcon = (result) => {
            switch (result) {
                case "VALID": return '<i class="bx bx-check-shield" style="font-size: 2rem;"></i>';
                case "EDITED": return '<i class="bx bx-edit" style="font-size: 2rem;"></i>';
                case "UNABLE TO VERIFY": return '<i class="bx bx-error" style="font-size: 2rem;"></i>';
                case "FAKE": return '<i class="bx bx-shield-x" style="font-size: 2rem;"></i>';
                default: return '<i class="bx bx-loader-alt bx-spin" style="font-size: 2rem;"></i>';
            }
        };

        const getStatusBadge = (status) => {
            if (status === "Matched" || status === "Match") {
                return '<span style="background: rgba(34, 197, 94, 0.2); color: var(--success); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">✓ Match</span>';
            } else if (status === "Mismatched" || status === "Mismatch") {
                return '<span style="background: rgba(239, 68, 68, 0.2); color: var(--danger); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">✗ Mismatch</span>';
            } else if (status === "Skipped" || status.includes("N/A")) {
                return '<span style="background: rgba(156, 163, 175, 0.2); color: var(--text-muted); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">⏸ Skipped</span>';
            }
            return `<span style="color: var(--text-muted);">${status}</span>`;
        };

        return `
        <div class="verification-report glass-card" style="padding: 1.5rem; margin-top: 1rem;">
            <!-- Header with Final Result -->
            <div style="display: flex; align-items: center; gap: 1rem; padding: 1.5rem; margin-bottom: 1.5rem; border-radius: 12px; background: ${getResultColor(vr.final_result)}20; border: 2px solid ${getResultColor(vr.final_result)};">
                <div style="color: ${getResultColor(vr.final_result)};">
                    ${getResultIcon(vr.final_result)}
                </div>
                <div>
                    <h2 style="margin: 0; color: ${getResultColor(vr.final_result)};">
                        ${vr.final_result}
                    </h2>
                    <p style="margin: 0.25rem 0 0 0; font-size: 0.85rem; color: var(--text-muted);">
                        Certificate Verification Result
                    </p>
                </div>
            </div>
            
            <!-- Layer 1: Hash Verification -->
            <div style="margin-bottom: 1.5rem;">
                <h4 style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                    <i class='bx bx-hash' style="color: var(--primary);"></i>
                    Layer 1: Hash Verification (SHA-256)
                </h4>
                <div style="padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; border-left: 3px solid ${vr.hash_verification.status === 'Matched' ? 'var(--success)' : vr.hash_verification.status === 'Mismatched' ? 'var(--danger)' : 'var(--warning)'};">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span style="font-weight: 600;">File Integrity Check</span>
                        ${getStatusBadge(vr.hash_verification.status)}
                    </div>
                    <p style="margin: 0; font-size: 0.85rem; color: var(--text-muted);">
                        ${vr.hash_verification.message || "Comparing file hash to detect modifications"}
                    </p>
                </div>
            </div>
            
            <!-- Layer 2: OCR Field Comparison -->
            <div style="margin-bottom: 1.5rem;">
                <h4 style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                    <i class='bx bx-scan' style="color: var(--primary);"></i>
                    Layer 2: OCR Field Comparison
                </h4>
                <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                    <div style="padding: 0.75rem 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span>Certificate Number</span>
                        ${getStatusBadge(vr.field_comparison.certificate_number)}
                    </div>
                    <div style="padding: 0.75rem 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span>Institution Name</span>
                        ${getStatusBadge(vr.field_comparison.institution_name)}
                    </div>
                    <div style="padding: 0.75rem 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <span>Verified Certificate Name</span>
                        ${getStatusBadge(vr.field_comparison.verified_certificate_name)}
                    </div>
                </div>
            </div>
            
            <!-- Remarks -->
            <div style="padding: 1rem; background: ${getResultColor(vr.final_result)}10; border-radius: 8px; border: 1px solid ${getResultColor(vr.final_result)}40;">
                <h4 style="margin: 0 0 0.5rem 0; display: flex; align-items: center; gap: 0.5rem;">
                    <i class='bx bx-info-circle'></i> Verification Summary
                </h4>
                <p style="margin: 0; font-size: 0.9rem;">
                    ${vr.remarks}
                </p>
            </div>
            
            <!-- Timestamp -->
            <p style="margin: 1rem 0 0 0; font-size: 0.75rem; color: var(--text-muted); text-align: right;">
                <i class='bx bx-time'></i> Verified at: ${new Date(report.timestamp).toLocaleString()}
            </p>
        </div>
        `;
    },

    /**
     * Generate text report for console/logging
     * @param {Object} report - Verification report from verify()
     * @returns {string} Text formatted report
     */
    generateTextReport: (report) => {
        const vr = report.certificate_verification_report;

        let text = "\n";
        text += "╔══════════════════════════════════════════════════════════════════╗\n";
        text += "║              CERTIFICATE VERIFICATION REPORT                     ║\n";
        text += "╠══════════════════════════════════════════════════════════════════╣\n";
        text += `║  Final Result: ${vr.final_result.padEnd(52)}║\n`;
        text += "╠══════════════════════════════════════════════════════════════════╣\n";
        text += "║  LAYER 1: Hash Verification (SHA-256)                            ║\n";
        text += `║    Status: ${vr.hash_verification.status.padEnd(55)}║\n`;
        text += "╠══════════════════════════════════════════════════════════════════╣\n";
        text += "║  LAYER 2: OCR Field Comparison                                   ║\n";
        text += `║    • Certificate Number:        ${vr.field_comparison.certificate_number.padEnd(33)}║\n`;
        text += `║    • Institution Name:          ${vr.field_comparison.institution_name.padEnd(33)}║\n`;
        text += `║    • Verified Certificate Name: ${vr.field_comparison.verified_certificate_name.padEnd(33)}║\n`;
        text += "╠══════════════════════════════════════════════════════════════════╣\n";
        text += "║  REMARKS:                                                        ║\n";

        // Word wrap remarks
        const words = vr.remarks.split(' ');
        let line = "║    ";
        for (const word of words) {
            if ((line + word).length > 68) {
                text += line.padEnd(69) + "║\n";
                line = "║    " + word + " ";
            } else {
                line += word + " ";
            }
        }
        if (line.trim() !== "║") {
            text += line.padEnd(69) + "║\n";
        }

        text += "╚══════════════════════════════════════════════════════════════════╝\n";

        return text;
    }
};

// Make CertificateVerifier globally accessible
window.CertificateVerifier = CertificateVerifier;


// ==========================================
// STATE MANAGEMENT & ROUTER
// ==========================================

const State = {
    user: null, // Current logged in user
    currentPage: 'login',
    notifications: [],

    // Actions
    navigate: (page) => {
        State.currentPage = page;
        Render.app();
    },

    loginUser: (user) => {
        State.user = user;
        // Redirect based on role
        if (user.role === 'ADMIN') State.navigate('admin-dashboard');
        else if (user.role === 'USER') State.navigate('user-dashboard');
        else if (user.role === 'VERIFIER') State.navigate('verifier-dashboard');
    },

    logout: () => {
        auth.signOut().catch(e => console.error(e));
    }
};




const Views = {
    login: () => `
        <div class="login-container">
            <div class="glass-card login-card animate-fade">
                <div style="text-align: center; margin-bottom: 2rem;">
                    <i class='bx bxs-cube-alt' style="font-size: 3rem; color: var(--primary);"></i>
                    <h2 class="mt-4">CertValid</h2>
                    <p style="color: var(--text-muted)">Secure Certificate Verification System</p>
                </div>
                
                <form onsubmit="Handlers.handleLogin(event)">
                    <div id="login-error" class="error-message" style="display: none; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); color: var(--danger); padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
                        <i class='bx bx-error-circle'></i> <span id="login-error-text"></span>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Email Address</label>
                        <input type="email" name="email" class="input-field" placeholder="name@example.com" required>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Password</label>
                        <input type="password" name="password" class="input-field" placeholder="••••••••" required>
                    </div>
                    <div style="text-align: right; margin-bottom: 1rem;">
                        <a href="#" onclick="State.navigate('forgot-password')" style="font-size: 0.8rem; color: var(--text-muted);">Forgot Password?</a>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-full justify-center">
                        Secure Login <i class='bx bx-log-in-circle'></i>
                    </button>
                    
                    <!-- Divider -->
                    <div class="mt-4" style="display: flex; align-items: center; gap: 1rem;">
                        <div style="flex: 1; height: 1px; background: var(--glass-border);"></div>
                        <span style="color: var(--text-muted); font-size: 0.85rem;">OR</span>
                        <div style="flex: 1; height: 1px; background: var(--glass-border);"></div>
                    </div>
                    
                    <!-- Google Sign-In -->
                    <button type="button" onclick="Handlers.handleGoogleSignIn()" class="btn btn-google w-full justify-center mt-4">
                        <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z" fill="#4285F4"/>
                            <path d="M9.003 18c2.43 0 4.467-.806 5.956-2.18l-2.909-2.26c-.806.54-1.836.86-3.047.86-2.344 0-4.328-1.584-5.036-3.711H.96v2.332C2.44 15.983 5.485 18 9.003 18z" fill="#34A853"/>
                            <path d="M3.964 10.712c-.18-.54-.282-1.117-.282-1.71 0-.593.102-1.17.282-1.71V4.96H.957C.347 6.175 0 7.55 0 9.002c0 1.452.348 2.827.957 4.042l3.007-2.332z" fill="#FBBC05"/>
                            <path d="M9.003 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.464.891 11.428 0 9.002 0 5.485 0 2.44 2.017.96 4.958l3.004 2.332c.708-2.127 2.692-3.71 5.036-3.71z" fill="#EA4335"/>
                        </svg>
                        Continue with Google
                    </button>
                    
                    <div class="mt-4" style="text-align: center; font-size: 0.9rem;">
                        <span style="color: var(--text-muted)">New User?</span> 
                        <a href="#" onclick="State.navigate('register')" style="color: var(--primary-light)">Create Account</a>
                    </div>
                     <div class="mt-4" style="text-align: center;">
                        <a href="#" onclick="State.navigate('public-verify')" style="color: var(--text-muted); text-decoration: underline;">Public Verification Portal</a>
                    </div>
                </form>

                <!-- Helper for Demo Removed -->
            </div>
        </div>
    `,

    register: () => `
        <div class="login-container">
            <div class="glass-card login-card animate-fade">
                <h2 style="margin-bottom: 1.5rem;">Create Account</h2>
                <form onsubmit="Handlers.handleRegister(event)">
                    <div class="input-group">
                        <label class="input-label">Full Name</label>
                        <input type="text" name="name" class="input-field" required>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Email</label>
                        <input type="email" name="email" class="input-field" required>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Register Number <span style="color: var(--danger);">*</span></label>
                        <input type="text" name="registerNumber" class="input-field" placeholder="e.g., CS20253072" required 
                               pattern="[A-Za-z0-9]+" title="Register number should contain only letters and numbers">
                        <small style="color: var(--text-muted); font-size: 0.75rem;">Your unique student/enrollment ID from your institution</small>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Password</label>
                        <input type="password" name="password" class="input-field" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-full justify-center">
                        Register
                    </button>
                    
                    <!-- Divider -->
                    <div class="mt-4" style="display: flex; align-items: center; gap: 1rem;">
                        <div style="flex: 1; height: 1px; background: var(--glass-border);"></div>
                        <span style="color: var(--text-muted); font-size: 0.85rem;">OR</span>
                        <div style="flex: 1; height: 1px; background: var(--glass-border);"></div>
                    </div>
                    
                    <!-- Google Sign-Up -->
                    <button type="button" onclick="Handlers.handleGoogleSignUp()" class="btn btn-google w-full justify-center mt-4">
                        <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z" fill="#4285F4"/>
                            <path d="M9.003 18c2.43 0 4.467-.806 5.956-2.18l-2.909-2.26c-.806.54-1.836.86-3.047.86-2.344 0-4.328-1.584-5.036-3.711H.96v2.332C2.44 15.983 5.485 18 9.003 18z" fill="#34A853"/>
                            <path d="M3.964 10.712c-.18-.54-.282-1.117-.282-1.71 0-.593.102-1.17.282-1.71V4.96H.957C.347 6.175 0 7.55 0 9.002c0 1.452.348 2.827.957 4.042l3.007-2.332z" fill="#FBBC05"/>
                            <path d="M9.003 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.464.891 11.428 0 9.002 0 5.485 0 2.44 2.017.96 4.958l3.004 2.332c.708-2.127 2.692-3.71 5.036-3.71z" fill="#EA4335"/>
                        </svg>
                        Sign up with Google
                    </button>
                    
                    <div class="mt-4" style="text-align: center;">
                        <a href="#" onclick="State.navigate('login')" style="color: var(--text-muted)">Back to Login</a>
                    </div>
                </form>
            </div>
        </div>
    `,

    'forgot-password': () => `
        <div class="login-container">
            <div class="glass-card login-card animate-fade">
                <div style="text-align: center; margin-bottom: 2rem;">
                    <i class='bx bxs-lock-open' style="font-size: 3rem; color: var(--primary);"></i>
                    <h2 class="mt-4">Reset Password</h2>
                    <p style="color: var(--text-muted)">Enter your email to receive a password reset link</p>
                </div>
                
                <form onsubmit="Handlers.handleForgotPassword(event); return false;">
                    <div id="forgot-error" style="display: none; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); color: var(--danger); padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
                    </div>
                    <div id="forgot-success" style="display: none; background: rgba(34, 197, 94, 0.1); border: 1px solid var(--success); color: var(--success); padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; text-align: center;">
                    </div>
                    
                    <div class="input-group">
                        <label class="input-label">Email Address</label>
                        <input type="email" id="forgot-email" class="input-field" placeholder="name@example.com" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-full justify-center">
                        <i class='bx bx-mail-send'></i> Send Reset Link
                    </button>
                    
                    <div class="mt-4" style="text-align: center;">
                        <a href="#" onclick="State.navigate('login')" style="color: var(--text-muted)">
                            <i class='bx bx-arrow-back'></i> Back to Login
                        </a>
                    </div>
                </form>
            </div>
        </div>
    `,

    // LAYOUT WRAPPER FOR DASHBOARDS
    dashboardLayout: (content, activeNav) => `
        <div class="dashboard-grid">
            <aside class="sidebar">
                <div class="flex items-center gap-4 mb-4" style="padding-bottom: 2rem; border-bottom: 1px solid var(--glass-border);">
                    <i class='bx bxs-cube-alt' style="font-size: 2rem; color: var(--primary);"></i>
                    <div>
                        <h3 style="font-size: 1.2rem;">CertValid</h3>
                        <span style="font-size: 0.8rem; color: var(--text-muted);">${State.user?.role} VIEW</span>
                    </div>
                </div>

                <nav>
                    ${State.user?.role === 'ADMIN' ? `
                        <a href="#" onclick="State.navigate('admin-dashboard')" class="nav-item ${activeNav === 'overview' ? 'active' : ''}">
                            <i class='bx bxs-dashboard'></i> Overview
                        </a>
                        <a href="#" onclick="State.navigate('admin-users')" class="nav-item ${activeNav === 'users' ? 'active' : ''}">
                            <i class='bx bxs-user-account'></i> User Mgmt.
                        </a>
                    ` : ''}

                    ${State.user?.role === 'USER' ? `
                        <a href="#" onclick="State.navigate('user-dashboard')" class="nav-item ${activeNav === 'upload' ? 'active' : ''}">
                            <i class='bx bxs-cloud-upload'></i> Upload Cert
                        </a>
                        <a href="#" onclick="State.navigate('user-history')" class="nav-item ${activeNav === 'history' ? 'active' : ''}">
                            <i class='bx bx-history'></i> My Certificates
                        </a>
                    ` : ''}

                    ${State.user?.role === 'VERIFIER' ? `
                         <a href="#" onclick="State.navigate('verifier-dashboard')" class="nav-item ${activeNav === 'search' ? 'active' : ''}">
                            <i class='bx bx-search-alt'></i> Verify Certificate
                        </a>
                    ` : ''}

                    <div style="margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--glass-border);">
                         <a href="#" onclick="State.logout()" class="nav-item">
                            <i class='bx bx-log-out'></i> Logout
                        </a>
                    </div>
                </nav>
            </aside>
            <main class="main-content">
                <header class="flex justify-between items-center mb-4">
                    <div class="flex items-center gap-4">
                        <button class="menu-toggle" onclick="Handlers.toggleSidebar()">
                            <i class='bx bx-menu'></i>
                        </button>
                        <h2 class="animate-fade">Dashboard</h2>
                    </div>
                    <div class="flex items-center gap-4">
                    ${State.user?.role === 'ADMIN' ? `
                        <button onclick="Wallet.connect()" id="wallet-btn" class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.8rem;">
                            <i class='bx bx-wallet'></i> Connect Wallet
                        </button>
                    ` : ''}
                        <span style="color: var(--text-muted)">Welcome, ${State.user?.name || 'Guest'}</span>
                        <div style="width: 40px; height: 40px; background: var(--primary); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold;">
                            ${State.user?.name ? State.user.name.charAt(0) : 'G'}
                        </div>
                    </div>
                </header>
                <div class="animate-fade">
                    ${content}
                </div>
            </main>
        </div>
    `
};

// ==========================================
// EVENT HANDLERS
// ==========================================

const Handlers = {
    toggleSidebar: () => {
        document.querySelector('.sidebar').classList.toggle('active');
    },

    handleLogin: async (e) => {
        e.preventDefault();
        const form = new FormData(e.target);
        const email = form.get('email');
        const pass = form.get('password');

        // Hide previous error
        const errorDiv = document.getElementById('login-error');
        const errorText = document.getElementById('login-error-text');
        if (errorDiv) errorDiv.style.display = 'none';

        try {
            const user = await API.login(email, pass);
            if (user) {
                State.loginUser(user);
            } else {
                if (errorDiv && errorText) {
                    errorText.textContent = 'Invalid credentials. Please try again.';
                    errorDiv.style.display = 'block';
                }
            }
        } catch (err) {
            console.error(err);
            // Show specific error messages based on Firebase error codes
            let errorMessage = 'Login failed. Please try again.';
            if (err.code === 'auth/wrong-password' || err.code === 'auth/invalid-credential') {
                errorMessage = 'Invalid password. Please check your password and try again.';
            } else if (err.code === 'auth/user-not-found') {
                errorMessage = 'No account found with this email. Please register first.';
            } else if (err.code === 'auth/invalid-email') {
                errorMessage = 'Invalid email format. Please enter a valid email.';
            } else if (err.code === 'auth/too-many-requests') {
                errorMessage = 'Too many failed attempts. Please try again later.';
            }
            if (errorDiv && errorText) {
                errorText.textContent = errorMessage;
                errorDiv.style.display = 'block';
            }
        }
    },

    handleRegister: async (e) => {
        e.preventDefault();
        const form = new FormData(e.target);
        const data = Object.fromEntries(form.entries());
        try {
            await API.register(data);
            alert('Registration Successful! Please Login.');
            State.navigate('login');
        } catch (err) {
            alert(err.message);
        }
    },

    handleForgotPassword: async (e) => {
        if (e) e.preventDefault();
        const emailInput = document.getElementById('forgot-email');
        const email = emailInput ? emailInput.value : '';

        if (!email) {
            const errorDiv = document.getElementById('forgot-error');
            if (errorDiv) {
                errorDiv.textContent = 'Please enter your email address.';
                errorDiv.style.display = 'block';
            }
            return;
        }

        try {
            await API.forgotPassword(email);
            // Show success message
            const successDiv = document.getElementById('forgot-success');
            const errorDiv = document.getElementById('forgot-error');
            if (errorDiv) errorDiv.style.display = 'none';
            if (successDiv) {
                successDiv.innerHTML = `<i class='bx bx-check-circle'></i> Password reset email sent to <strong>${email}</strong>. Check your inbox.`;
                successDiv.style.display = 'block';
            }
        } catch (err) {
            const errorDiv = document.getElementById('forgot-error');
            let errorMessage = 'Failed to send reset email. Please try again.';
            if (err.code === 'auth/user-not-found') {
                errorMessage = 'No account found with this email address.';
            } else if (err.code === 'auth/invalid-email') {
                errorMessage = 'Invalid email format.';
            }
            if (errorDiv) {
                errorDiv.textContent = errorMessage;
                errorDiv.style.display = 'block';
            }
        }
    },

    // Google Sign-In Handler (Login Page)
    handleGoogleSignIn: async () => {
        try {
            const user = await API.googleSignIn('USER');
            if (user) {
                State.loginUser(user);
            }
        } catch (err) {
            if (err.code === 'auth/popup-closed-by-user') {
                console.log('Sign-in popup closed');
            } else {
                alert("Google Sign-In Failed: " + (err.message || err));
            }
        }
    },

    // Google Sign-Up Handler (Register Page - respects role selection)
    handleGoogleSignUp: async () => {
        try {
            // Get selected role from the form
            const roleSelect = document.querySelector('select[name="role"]');
            const selectedRole = roleSelect ? roleSelect.value : 'USER';

            const user = await API.googleSignIn(selectedRole);
            if (user) {
                alert(`Welcome ${user.name}! You are registered as ${user.role}.`);
                State.loginUser(user);
            }
        } catch (err) {
            if (err.code === 'auth/popup-closed-by-user') {
                console.log('Sign-up popup closed');
            } else {
                alert("Google Sign-Up Failed: " + (err.message || err));
            }
        }
    }
};

// ==========================================
// MAIN RENDER FUNCTION
// ==========================================

const Render = {
    hydrateAdminOverview: async () => {
        const container = document.getElementById('admin-overview-container');
        if (!container) return;

        container.innerHTML = `<div class="loader" style="margin: 2rem auto;"></div><p style="text-align:center;">Loading and syncing with blockchain...</p>`;

        const certs = await DB.getAllCertificates();

        // Check blockchain for pending certificates and sync status
        let syncCount = 0;
        for (const cert of certs) {
            if (cert.status === 'PENDING') {
                try {
                    console.log(`[SYNC] Checking blockchain for ${cert.id}...`);
                    const chainData = await Blockchain.verifyCertificate(cert.id);
                    if (chainData && chainData.exists) {
                        console.log(`[SYNC] ${cert.id} found on blockchain! Updating status...`);
                        await DB.updateCertificateStatus(cert.id, 'VERIFIED', null, chainData.issuerAddress);
                        cert.status = 'VERIFIED'; // Update local reference
                        syncCount++;
                    }
                } catch (e) {
                    console.warn(`[SYNC] Could not check ${cert.id}:`, e.message);
                }
            }
        }

        if (syncCount > 0) {
            console.log(`[SYNC] Synced ${syncCount} certificate(s) from blockchain`);
        }

        const pending = certs.filter(c => c.status === 'PENDING');
        const verified = certs.filter(c => c.status === 'VERIFIED');

        container.innerHTML = `
            <div class="grid" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; margin-bottom: 2rem;">
                 <div class="glass-card">
                    <span style="color: var(--text-muted)">Total Certificates</span>
                    <h2>${certs.length}</h2>
                 </div>
                 <div class="glass-card">
                    <span style="color: var(--warning)">Pending Approval</span>
                    <h2>${pending.length}</h2>
                 </div>
                 <div class="glass-card">
                    <span style="color: var(--success)">Verified On-Chain</span>
                    <h2>${verified.length}</h2>
                 </div>
            </div>

            ${syncCount > 0 ? `
                <div style="background: rgba(34,197,94,0.1); border: 1px solid var(--success); padding: 1rem; border-radius: var(--radius-sm); margin-bottom: 1.5rem;">
                    <i class='bx bx-check-circle' style="color: var(--success);"></i> 
                    Synced ${syncCount} certificate(s) from blockchain!
                </div>
            ` : ''}

            <div class="glass-card">
                <div class="flex justify-between items-center mb-4">
                    <h3>Pending Approvals (Institution Simulation)</h3>
                    <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.8rem;" onclick="Render.hydrateAdminOverview()">
                        <i class='bx bx-refresh'></i> Sync with Blockchain
                    </button>
                </div>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
                    *In a real system, these would be handled via Email Links by the University. As Admin/Demo, you can override here.
                </p>

                ${pending.length === 0 ? '<p>No pending certificates.</p>' : `
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; text-align: left; border-collapse: collapse;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--glass-border); color: var(--text-muted);">
                                    <th style="padding: 1rem;">ID</th>
                                    <th style="padding: 1rem;">Student</th>
                                    <th style="padding: 1rem;">Institution</th>
                                    <th style="padding: 1rem;">Actions</th>
                                </tr>
                            </thead>
                        <tbody>
                            ${pending.map(c => `
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                                    <td style="padding: 1rem;">${c.id}</td>
                                    <td style="padding: 1rem;">${c.data.name}</td>
                                    <td style="padding: 1rem;">${c.data.institution}</td>
                                    <td style="padding: 1rem;">
                                        <div class="flex gap-2">
                                            <button class="btn btn-secondary" style="padding: 6px; font-size: 0.8rem;" onclick="Handlers.showDocument('${c.data.image}', '${c.data.fileType || 'image'}')">
                                                <i class='bx bx-show'></i> View ${c.data.fileType === 'pdf' ? 'PDF' : 'Image'}
                                            </button>
                                            <button class="btn btn-success" style="padding: 6px; background: rgba(34,197,94,0.2); color: var(--success); border:none; cursor:pointer;" onclick="Handlers.adminVerify('${c.id}', true)">
                                                <i class='bx bxs-check-shield'></i> Write to Blockchain
                                            </button>
                                            <button class="btn btn-danger" style="padding: 6px; background: rgba(239,68,68,0.2); color: var(--danger); border:none; cursor:pointer;" onclick="Handlers.adminVerify('${c.id}', false)">
                                                <i class='bx bx-x'></i> Reject
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `}
            </div>
        `;
    },

    app: () => {
        const app = document.getElementById('app');

        switch (State.currentPage) {
            case 'login':
                app.innerHTML = Views.login();
                break;
            case 'register':
                app.innerHTML = Views.register();
                break;
            case 'forgot-password':
                app.innerHTML = Views['forgot-password']();
                break;



            // USER ROUTES
            case 'user-dashboard':
                app.innerHTML = Views.dashboardLayout(Views.userUpload(), 'upload');
                break;
            case 'user-history':
                app.innerHTML = Views.dashboardLayout(Views.userHistory(), 'history');
                break;

            // VERIFIER ROUTES
            case 'verifier-dashboard':
                app.innerHTML = Views.dashboardLayout(Views.verifierSearch(), 'search');
                break;

            // ADMIN ROUTES
            case 'admin-dashboard':
                app.innerHTML = Views.dashboardLayout(Views.adminOverview(), 'overview');
                break;
            case 'admin-users':
                app.innerHTML = Views.dashboardLayout(Views.adminUsers(), 'users');
                break;

            // PUBLIC ROUTE
            case 'public-verify':
                app.innerHTML = `
                    <div class="container" style="padding-top: 4rem;">
                        <header class="flex justify-between items-center mb-4">
                            <div class="flex items-center gap-4">
                                <i class='bx bxs-cube-alt' style="font-size: 2rem; color: var(--primary);"></i>
                                <h2>CertValid Public</h2>
                            </div>
                            <div class="flex gap-4">
                                <button onclick="State.navigate('login')" class="btn btn-secondary">Login</button>
                            </div>
                        </header>
                        ${Views.publicVerifyPage()}
                    </div>
                 `;
                break;

            default:
                app.innerHTML = '<h1>404 Page Not Found</h1>';
        }
    }
}

// ==========================================
// ADDITIONAL COMPONENT VIEWS (USER)
// ==========================================

Views.userUpload = () => `
    <div class="glass-card" style="max-width: 800px; margin: 0 auto;">
        <h3>Upload Certificate</h3>
        <p class="mb-4" style="color: var(--text-muted)">Upload your degree/certificate to start the verification process.</p>
        
        <div id="upload-step-1">
            <div class="file-upload-zone" onclick="document.getElementById('fileInput').click()">
                <i class='bx bxs-cloud-upload' style="font-size: 3rem; color: var(--primary);"></i>
                <h4 class="mt-4">Click to Upload or Drag File</h4>
                <p style="color: var(--text-muted)">Supports PNG, JPG, PDF (Max 5MB)</p>
                <input type="file" id="fileInput" hidden onchange="Handlers.handleFileUpload(this)">
            </div>
        </div>

        <div id="upload-step-2" class="hidden mt-8">
            <div class="flex items-center gap-4 mb-4">
                <div class="loader" style="width: 24px; height: 24px;"></div>
                <span>Analyzing Certificate with OCR AI...</span>
            </div>
        </div>

        <div id="upload-step-3" class="hidden mt-8">
            <div style="background: rgba(15, 23, 42, 0.5); padding: 1.5rem; border-radius: var(--radius-sm); border: 1px solid var(--glass-border);">
                <h4 style="margin-bottom: 1rem; color: var(--primary-light)">Extracted Details</h4>
                <div class="grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                    <div>
                        <label class="input-label">Student Name</label>
                        <input type="text" id="ocr-name" class="input-field">
                    </div>
                    <div>
                        <label class="input-label">Register Number</label>
                        <input type="text" id="ocr-reg" class="input-field">
                    </div>
                    <div>
                        <label class="input-label">Institution</label>
                        <input type="text" id="ocr-inst" class="input-field" placeholder="e.g., Dr N.G.P Institute of Technology">
                    </div>
                    <div>
                        <label class="input-label">Organized By</label>
                        <input type="text" id="ocr-organizer" class="input-field" placeholder="e.g., Centre for Internet of Things">
                    </div>
                    <div>
                        <label class="input-label">Degree/Program</label>
                        <input type="text" id="ocr-degree" class="input-field">
                    </div>
                </div>
                
                <div class="mt-8 flex gap-4">
                    <button class="btn btn-secondary w-full justify-center" onclick="Handlers.resetUpload()">Cancel</button>
                    <button class="btn btn-primary w-full justify-center" onclick="Handlers.submitCertificate(event)">
                        <i class='bx bx-check-shield'></i> Submit for Verification
                    </button>
                </div>
            </div>
        </div>
    </div>
`;

Views.userHistory = () => {
    setTimeout(async () => {
        const container = document.getElementById('user-history-list');
        if (!container) return;

        const certs = await DB.getCertificatesByUser(State.user.id);

        if (certs.length === 0) {
            container.innerHTML = `
                <div class="glass-card" style="text-align: center; padding: 4rem;">
                    <i class='bx bx-file-blank' style="font-size: 3rem; color: var(--text-muted);"></i>
                    <h3 class="mt-4">No Certificates Uploaded</h3>
                    <button class="btn btn-primary mt-4" onclick="State.navigate('user-dashboard')">Upload Now</button>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="glass-card">
                <h3>My Certificates</h3>
                <div style="margin-top: 1.5rem;">
                    ${certs.map(cert => `
                        <div style="display: flex; align-items: center; justify-content: space-between; padding: 1rem; border-bottom: 1px solid var(--glass-border);">
                            <div>
                                <h4 style="color: var(--primary-light)">${cert.data.degree}</h4>
                                <div style="font-size: 0.9rem; color: var(--text-muted);">
                                    ${cert.data.institution} • ${cert.uploadedAt}
                                </div>
                            </div>
                            <div class="flex items-center gap-4">
                                <span class="status-badge ${cert.status === 'VERIFIED' ? 'status-verified' : cert.status === 'PENDING' ? 'status-pending' : 'status-invalid'}">
                                    ${cert.status}
                                </span>
                                ${cert.status === 'VERIFIED' ? `
                                    <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.8rem;" onclick="Handlers.downloadReport('${cert.id}')">
                                        <i class='bx bxs-download'></i> Report
                                    </button>
                                ` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }, 100);

    return `<div id="user-history-list"><div class="loader" style="margin: 2rem auto;"></div></div>`;
};

// ==========================================
// ADDITIONAL HANDLERS (USER)
// ==========================================

Handlers.currentOcrData = null;

Handlers.handleFileUpload = async (input) => {
    const file = input.files[0];
    if (!file) return;

    // Validate size (Max 500KB for Firestore safety)
    if (file.size > 500 * 1024) {
        alert("File too large! Please upload a file under 500KB.");
        input.value = "";
        return;
    }

    // Detect file type
    const isPdf = file.type === 'application/pdf';
    const fileType = isPdf ? 'pdf' : 'image';

    // Show Loader
    document.getElementById('upload-step-1').classList.add('hidden');
    document.getElementById('upload-step-2').classList.remove('hidden');

    try {
        // 1. Convert to Base64
        const base64 = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = () => resolve(reader.result);
            reader.onerror = error => reject(error);
        });

        // 2. Run OCR (works for images, PDFs may have limited results)
        const data = await API.ocrExtract(base64);

        // 3. Get user's registered register number
        const userRegNumber = State.user?.registerNumber || '';

        // 4. Check if OCR register number matches user's registered one
        let registerNumberMismatch = false;
        if (userRegNumber && data.registerNumber) {
            const ocrReg = data.registerNumber.toUpperCase().replace(/\s/g, '');
            const userReg = userRegNumber.toUpperCase().replace(/\s/g, '');
            if (ocrReg !== userReg && ocrReg.length > 3) {
                registerNumberMismatch = true;
                alert(`⚠️ Warning: The register number in the certificate (${ocrReg}) does not match your registered number (${userReg}).\n\nPlease verify you are uploading the correct certificate.`);
            }
        }

        // 5. Attach Document Data with file type
        Handlers.currentOcrData = { ...data, image: base64, fileType: fileType };

        // Show Results
        document.getElementById('upload-step-2').classList.add('hidden');
        document.getElementById('upload-step-3').classList.remove('hidden');

        // Fill Form - Use user's registered register number (not OCR result)
        document.getElementById('ocr-name').value = data.name;
        document.getElementById('ocr-reg').value = userRegNumber || data.registerNumber; // Prefer user's registered number
        document.getElementById('ocr-inst').value = data.institution || '';
        document.getElementById('ocr-organizer').value = data.organizer || '';
        document.getElementById('ocr-degree').value = data.degree;

        // Show mismatch warning if applicable
        if (registerNumberMismatch) {
            const regField = document.getElementById('ocr-reg');
            regField.style.borderColor = 'var(--warning)';
            regField.style.background = 'rgba(251, 191, 36, 0.1)';
        }
    } catch (err) {
        alert(err);
        Handlers.resetUpload();
    }
};

Handlers.resetUpload = () => {
    State.navigate('user-dashboard'); // Reloads view
};


Handlers.submitCertificate = async (event) => {
    if (event) event.preventDefault();
    if (!Handlers.currentOcrData) return;

    // 1. Capture potentially edited values from UI
    const name = document.getElementById('ocr-name').value;
    const reg = document.getElementById('ocr-reg').value;
    const inst = document.getElementById('ocr-inst').value;
    const organizer = document.getElementById('ocr-organizer').value;
    const degree = document.getElementById('ocr-degree').value;

    // Update the data object to be uploaded
    const dataToUpload = {
        ...Handlers.currentOcrData,
        name: name,
        registerNumber: reg,
        institution: inst,
        organizer: organizer,
        degree: degree
    };

    const btn = document.querySelector('#upload-step-3 .btn-primary');
    const originalText = btn ? btn.innerHTML : "Submit for Verification";

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<div class="loader" style="width: 16px; height: 16px; border-width: 2px;"></div> Uploading IPFS...`;
    }

    try {
        // 2. IPFS Upload
        const ipfsHash = await IPFS.upload(dataToUpload);

        if (btn) btn.innerHTML = `<div class="loader" style="width: 16px; height: 16px; border-width: 2px;"></div> Saving to DB...`;

        // 3. Create Record (Pending Blockchain Write by Admin)
        const newCert = {
            id: 'CERT-' + Math.floor(Math.random() * 1000000),
            userId: State.user.id,
            data: { ...dataToUpload },
            ipfsHash: ipfsHash,
            status: 'PENDING',
            uploadedAt: new Date().toLocaleDateString(),
            txHash: null,
            issuer: null
        };
        // 4. Save to Firestore
        await DB.addCertificate(newCert);

        alert('Certificate Uploaded to IPFS! Sent to Admin for Blockchain Verification.');
        State.navigate('user-history');

    } catch (err) {
        alert("Submission Failed: " + err.message);
    } finally {
        if (btn) {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    }
};

Handlers.downloadReport = async (id) => {
    try {
        const cert = await DB.getCertificateById(id);
        if (!cert) throw new Error("Certificate not found");

        const content = `VERIFICATION REPORT\n\nID: ${cert.id}\nStatus: ${cert.status}\nBlockchain Hash: ${cert.txHash}\nIPFS: ${cert.ipfsHash}`;

        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${cert.id}.txt`;
        a.click();
    } catch (err) {
        alert(err.message);
    }
};

// ==========================================
// ADDITIONAL COMPONENT VIEWS (VERIFIER & ADMIN)
// ==========================================

Views.adminUsers = () => {
    // Trigger Hydration
    setTimeout(async () => {
        try {
            const users = await DB.getAllUsers();
            const tbody = document.getElementById('admin-users-table');
            if (!tbody) return;

            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="padding:2rem; text-align:center;">No users found.</td></tr>';
                return;
            }

            tbody.innerHTML = users.map(u => `
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <td style="padding: 1rem;">${u.name || 'Unknown'}</td>
                    <td style="padding: 1rem;">${u.email}</td>
                    <td style="padding: 1rem;">
                        <span class="status-badge" style="background: rgba(99,102,241,0.15); color: var(--primary-light);">
                            ${u.role || 'USER'}
                        </span>
                    </td>
                    <td style="padding: 1rem;">${u.createdAt ? new Date(u.createdAt).toLocaleDateString() : 'N/A'}</td>
                    <td style="padding: 1rem;">
                        <button class="btn btn-danger" style="padding: 4px 8px; font-size: 0.75rem; background: rgba(239,68,68,0.2); color: var(--danger); border: none; cursor: pointer;" onclick="Handlers.handleDeleteUser('${u.id}', '${u.email}')">
                            <i class='bx bx-trash'></i> Delete
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (e) {
            console.error(e);
            const tbody = document.getElementById('admin-users-table');
            if (tbody) {
                if (e.code === 'permission-denied') {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="5" style="padding:2rem; text-align:center; color: var(--danger);">
                                <i class='bx bxs-lock-alt' style="font-size: 2rem; margin-bottom: 0.5rem;"></i><br>
                                <strong>Permission Denied</strong><br>
                                Firestore Rules blocked this request.<br>
                                <span style="font-size: 0.8rem; color: var(--text-muted)">Please deploy the new firestore.rules</span>
                            </td>
                        </tr>`;
                } else {
                    tbody.innerHTML = '<tr><td colspan="5" style="padding:2rem; text-align:center; color: var(--danger);">Error loading users: ' + e.message + '</td></tr>';
                }
            }
        }
    }, 100);

    return `
        <div class="glass-card">
            <div class="flex justify-between items-center mb-4">
                <h3>User Management</h3>
                <button class="btn btn-primary" onclick="Handlers.toggleCreateAdminModal()">
                    <i class='bx bx-user-plus'></i> Create New Admin
                </button>
            </div>
            
            <!-- HIDDEN MODAL FOR CREATING ADMIN -->
            <div id="create-admin-form" class="hidden" style="margin-bottom: 2rem; padding: 1.5rem; background: rgba(255,255,255,0.05); border-radius: var(--radius-sm);">
                <h4 style="margin-bottom: 1rem; color: var(--primary-light);">Register New System Administrator</h4>
                <form onsubmit="Handlers.handleCreateAdmin(event)">
                    <div class="grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                        <input type="text" name="name" class="input-field" placeholder="Admin Name" required>
                        <input type="email" name="email" class="input-field" placeholder="Email Address" required>
                    </div>
                    <div class="grid" style="display: grid; grid-template-columns: 1fr; gap: 1rem; margin-top: 1rem;">
                        <input type="password" name="password" class="input-field" placeholder="Secure Password" required>
                    </div>
                    <div class="flex gap-4 mt-4">
                        <button type="button" class="btn btn-secondary" onclick="Handlers.toggleCreateAdminModal()">Cancel</button>
                        <button type="submit" class="btn btn-primary">Create Admin User</button>
                    </div>
                </form>
            </div>

            <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.5rem;">
                Manage registered users and verified entities.
            </p>
            <div style="overflow-x: auto;">
                <table style="width: 100%; text-align: left; border-collapse: collapse;">
                    <thead>
                        <tr style="border-bottom: 1px solid var(--glass-border); color: var(--text-muted);">
                            <th style="padding: 1rem;">Name</th>
                            <th style="padding: 1rem;">Email</th>
                            <th style="padding: 1rem;">Role</th>
                            <th style="padding: 1rem;">Joined</th>
                            <th style="padding: 1rem;">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="admin-users-table">
                         <tr><td colspan="5" style="padding:2rem; text-align:center;">Loading Users...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;
};

Views.verifierSearch = () => `
    <div class="glass-card" style="max-width: 800px; margin: 0 auto;">
        <h3>Verify Certificate Authenticity</h3>
        <p class="mb-4" style="color: var(--text-muted)">Enter the Certificate ID or IPFS Hash to verify authenticity on the Blockchain.</p>
        
        <form onsubmit="Handlers.handleVerificationSearch(event)">
            <div class="flex gap-4">
                <input type="text" name="searchQuery" class="input-field" placeholder="e.g. CERT-X7Y2Z9..." required>
                <button type="submit" class="btn btn-primary">Search</button>
            </div>
        </form>

        <div id="verification-result" class="mt-8 hidden">
             <!-- Result injected here -->
        </div>
    </div>
`;

// ==========================================
// PUBLIC VERIFICATION PAGE (Two-Layer Verification)
// ==========================================
Views.publicVerifyPage = () => `
    <div class="public-verify-container" style="max-width: 1000px; margin: 0 auto;">
        <!-- Header -->
        <div class="glass-card" style="text-align: center; padding: 2rem; margin-bottom: 2rem;">
            <i class='bx bx-shield-quarter' style="font-size: 3rem; color: var(--primary); margin-bottom: 1rem;"></i>
            <h2 style="margin-bottom: 0.5rem;">Certificate Verification Portal</h2>
            <p style="color: var(--text-muted); max-width: 600px; margin: 0 auto;">
                Verify the authenticity of your certificate using our two-layer security system:
                SHA-256 hash verification and OCR-based field comparison.
            </p>
        </div>

        <!-- Verification Form -->
        <div class="glass-card" style="padding: 2rem; margin-bottom: 2rem;">
            <h3 style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1.5rem;">
                <i class='bx bx-search-alt' style="color: var(--primary);"></i>
                Step 1: Lookup Original Certificate
            </h3>
            
            <form id="lookup-form" onsubmit="Handlers.handleCertificateLookup(event)">
                <div class="input-group">
                    <label class="input-label">Certificate Number / ID</label>
                    <div class="flex gap-4">
                        <input type="text" id="cert-lookup-id" class="input-field" 
                               placeholder="Enter certificate number (e.g., CERT2025001)" required>
                        <button type="submit" class="btn btn-primary" id="lookup-btn">
                            <i class='bx bx-search'></i> Lookup
                        </button>
                    </div>
                </div>
            </form>
            
            <!-- Lookup Result -->
            <div id="lookup-result" class="mt-4" style="display: none;">
                <!-- Will be populated by JavaScript -->
            </div>
        </div>

        <!-- Upload Section (Hidden until lookup is successful) -->
        <div id="upload-section" class="glass-card" style="padding: 2rem; margin-bottom: 2rem; display: none;">
            <h3 style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1.5rem;">
                <i class='bx bx-upload' style="color: var(--primary);"></i>
                Step 2: Upload Certificate for Verification
            </h3>
            
            <div class="upload-zone" id="verify-upload-zone" 
                 onclick="document.getElementById('verify-file-input').click()"
                 ondrop="Handlers.handleVerifyFileDrop(event)"
                 ondragover="event.preventDefault(); this.classList.add('dragover')"
                 ondragleave="this.classList.remove('dragover')"
                 style="border: 2px dashed var(--glass-border); border-radius: 12px; padding: 3rem; text-align: center; cursor: pointer; transition: all 0.3s;">
                <i class='bx bx-cloud-upload' style="font-size: 3rem; color: var(--primary); margin-bottom: 1rem;"></i>
                <p style="font-weight: 600;">Click to Upload or Drag & Drop</p>
                <p style="color: var(--text-muted); font-size: 0.85rem;">Supports PNG, JPG, PDF (Max 5MB)</p>
            </div>
            <input type="file" id="verify-file-input" accept="image/*,.pdf" style="display: none;" 
                   onchange="Handlers.handleVerifyFileSelect(this)">
            
            <!-- File Preview -->
            <div id="verify-file-preview" class="mt-4" style="display: none;">
                <div style="display: flex; align-items: center; gap: 1rem; padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 8px;">
                    <i class='bx bx-file' style="font-size: 2rem; color: var(--primary);"></i>
                    <div style="flex: 1;">
                        <p id="verify-file-name" style="font-weight: 600; margin: 0;">filename.png</p>
                        <p id="verify-file-size" style="color: var(--text-muted); font-size: 0.85rem; margin: 0;">1.2 MB</p>
                    </div>
                    <button onclick="Handlers.resetVerifyUpload()" class="btn btn-danger" style="padding: 0.5rem 1rem;">
                        <i class='bx bx-x'></i>
                    </button>
                </div>
            </div>
            
            <!-- Verify Button -->
            <div class="mt-4" style="text-align: center;">
                <button id="verify-btn" onclick="Handlers.runTwoLayerVerification()" class="btn btn-primary" 
                        style="padding: 1rem 3rem; font-size: 1.1rem;" disabled>
                    <i class='bx bx-shield-quarter'></i> Run Two-Layer Verification
                </button>
            </div>
        </div>

        <!-- Verification Results -->
        <div id="verification-results" class="glass-card" style="padding: 2rem; display: none;">
            <h3 style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1.5rem;">
                <i class='bx bx-check-shield' style="color: var(--primary);"></i>
                Verification Results
            </h3>
            <div id="verification-report-container">
                <!-- Verification report will be injected here -->
            </div>
        </div>


    </div>
`;

Views.adminOverview = () => {
    // Trigger Hydration via Render
    setTimeout(() => {
        if (Render.hydrateAdminOverview) Render.hydrateAdminOverview();
    }, 100);

    return `
        <div id="admin-overview-container">
            <div class="loader" style="margin: 2rem auto;"></div>
            <p style="text-align:center;">Loading Dashboard Data...</p>
        </div>
    `;
};



Views.documentModal = (base64, fileType = 'image') => `
    <div id="document-modal" style="position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.9); z-index:1000; display:flex; justify-content:center; align-items:center; flex-direction:column;">
        <div style="position:relative; width:90%; max-width:900px; height:90%; display:flex; flex-direction:column; align-items:center;">
            <button onclick="document.getElementById('document-modal').remove()" style="position:absolute; top:-2.5rem; right:0; color:white; background:rgba(255,255,255,0.1); border:none; font-size:1.5rem; cursor:pointer; padding:0.5rem 1rem; border-radius:var(--radius-sm); z-index:1001;">&times; Close</button>
            ${fileType === 'pdf' ? `
                <embed src="${base64}" type="application/pdf" style="width:100%; height:100%; border-radius: var(--radius-sm); box-shadow: 0 4px 20px rgba(0,0,0,0.5);">
            ` : `
                <img src="${base64}" style="max-width:100%; max-height:90vh; border-radius: var(--radius-sm); box-shadow: 0 4px 20px rgba(0,0,0,0.5); object-fit:contain;">
            `}
        </div>
    </div>
`;

// Legacy support for showImage calls
Views.imageModal = (src) => Views.documentModal(src, 'image');

Handlers.showDocument = (base64, fileType = 'image') => {
    if (!base64) return alert("No document available for this certificate.");
    const modalHtml = Views.documentModal(base64, fileType);
    document.body.insertAdjacentHTML('beforeend', modalHtml);
};

// Legacy support
Handlers.showImage = (base64) => {
    Handlers.showDocument(base64, 'image');
};

// ==========================================
// ADDITIONAL HANDLERS (VERIFIER & ADMIN)
// ==========================================

Handlers.handleVerificationSearch = async (e) => {
    e.preventDefault();
    const query = new FormData(e.target).get('searchQuery').trim();
    const resultDiv = document.getElementById('verification-result');

    resultDiv.innerHTML = `<div class="loader" style="margin: 0 auto;"></div><p style="text-align:center; margin-top:10px;">Querying Smart Contract...</p>`;
    resultDiv.classList.remove('hidden');

    try {
        // 1. Read from Blockchain
        const chainData = await Blockchain.verifyCertificate(query);

        if (!chainData || !chainData.exists) {
            throw new Error("Certificate not found on Blockchain.");
        }

        // 2. Fetch Details from IPFS first
        resultDiv.innerHTML = `<div class="loader" style="margin: 0 auto;"></div><p style="text-align:center; margin-top:10px;">Blockchain Verified! Fetching Metadata...</p>`;

        let ipfsData = null;
        let dbData = null;

        // Try IPFS first
        if (chainData.ipfsHash) {
            ipfsData = await IPFS.fetch(chainData.ipfsHash);
        }

        // Fallback to Database if IPFS fails
        if (!ipfsData) {
            resultDiv.innerHTML = `<div class="loader" style="margin: 0 auto;"></div><p style="text-align:center; margin-top:10px;">IPFS unavailable, checking database...</p>`;
            dbData = await DB.getCertificateById(query);
        }

        // Use IPFS data or fallback to DB data
        const certDetails = ipfsData || (dbData ? dbData.data : null);
        const dataSource = ipfsData ? 'IPFS' : (dbData ? 'Database' : null);

        resultDiv.innerHTML = `
            <div style="padding: 2rem; background: rgba(34,197,94,0.1); border: 1px solid var(--success); border-radius: var(--radius-md);">
                <div class="flex items-center gap-4 mb-4">
                    <i class='bx bxs-badge-check' style="font-size: 3rem; color: var(--success)"></i>
                    <div>
                        <h3>Valid Certificate</h3>
                        <p>Authenticity Confirmed via Ethereum Blockchain</p>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 2rem; font-size: 0.95rem;">
                        <div><strong>Issuer Name:</strong> ${chainData.issuerName}</div>
                        <div><strong>Issuer Address:</strong> <span style="font-family:monospace; font-size:0.8rem;">${chainData.issuerAddress}</span></div>
                        <div><strong>Issued At:</strong> ${chainData.issuedAt}</div>
                        <div><strong>IPFS Hash:</strong> <span style="font-family:monospace; font-size:0.8rem;">${chainData.ipfsHash}</span></div>
                        
                        ${certDetails ? `
                        <div style="grid-column: span 2; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--glass-border);">
                            <h4 style="margin-bottom:0.5rem;">Student Details (From ${dataSource})</h4>
                            <p><strong>Name:</strong> ${certDetails.name || 'N/A'}</p>
                            <p><strong>Degree:</strong> ${certDetails.degree || 'N/A'}</p>
                            <p><strong>Institution:</strong> ${certDetails.institution || 'N/A'}</p>
                            
                            <!-- Display Document if Available -->
                            ${certDetails.image ? `
                                <div style="margin-top: 1rem; text-align: center;">
                                    <p style="margin-bottom: 0.5rem; color: var(--text-muted);">Certificate Copy:</p>
                                    ${certDetails.fileType === 'pdf' ? `
                                        <button class="btn btn-primary" style="padding: 10px 20px;" onclick="Handlers.showDocument('${certDetails.image}', 'pdf')">
                                            <i class='bx bxs-file-pdf'></i> View PDF Certificate
                                        </button>
                                    ` : `
                                        <img src="${certDetails.image}" style="max-width: 100%; border-radius: var(--radius-sm); border: 1px solid var(--glass-border); cursor: pointer;" onclick="Handlers.showDocument('${certDetails.image}', 'image')">
                                    `}
                                </div>
                            ` : ''}
                        </div>
                        ` : '<div style="grid-column: span 2; margin-top:1rem; color:var(--warning);"><i>Details could not be loaded from IPFS or Database.</i></div>'}
                </div>
            </div>
        `;

    } catch (err) {
        resultDiv.innerHTML = `
            <div style="text-align: center; color: var(--danger); padding: 1rem; border: 1px solid var(--danger); border-radius: var(--radius-sm);">
                <i class='bx bxs-error-circle' style="font-size: 2rem;"></i>
                <h4>Verification Failed</h4>
                <p>${err.message}</p>
            </div>
        `;
    }
};

Handlers.adminVerify = async (id, approve) => {
    if (!confirm(`Are you sure you want to ${approve ? 'ISSUE ON BLOCKCHAIN' : 'REJECT'}? This incurs gas fees.`)) return;

    if (!approve) {
        // Reject locally in DB
        await DB.updateCertificateStatus(id, 'INVALID');
        alert("Certificate Rejected.");
        // Refresh View
        Render.hydrateAdminOverview && Render.hydrateAdminOverview();
        State.navigate('admin-dashboard'); // Fallback refresh
        return;
    }

    // Blockchain Write
    try {
        const cert = await DB.getCertificateById(id);
        if (!cert) return;

        alert("Please confirm the transaction in MetaMask...");

        // Write to Contract: addCertificate(id, ipfsHash, institutionName)
        const tx = await Blockchain.writeCertificate(cert.id, cert.ipfsHash, cert.data.institution);

        alert(`Transaction Sent! Hash: ${tx.hash}\nWaiting for confirmation...`);
        const receipt = await tx.wait(); // Wait for mining

        // Update DB
        const issuer = await Wallet.address;
        await DB.updateCertificateStatus(id, 'VERIFIED', tx.hash, issuer);

        alert("Certificate Successfully Issued on Blockchain!");
        // Force refresh
        await Render.hydrateAdminOverview();
        State.navigate('admin-dashboard');

    } catch (err) {
        alert("Blockchain Error: " + (err.message || err));
    }
};

Handlers.toggleCreateAdminModal = () => {
    const formInfo = document.getElementById('create-admin-form');
    if (formInfo) formInfo.classList.toggle('hidden');
};

Handlers.handleCreateAdmin = async (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    const name = form.get('name');
    const email = form.get('email');
    const pass = form.get('password');

    try {
        alert("Creating new Admin User... Please Wait.");
        await API.createAdminUser(name, email, pass);
        alert(`SUCCESS: Admin ${email} created successfully!`);

        // Close Modal & Refresh
        Handlers.toggleCreateAdminModal();
        State.navigate('admin-users'); // Reload view

    } catch (err) {
        alert("Failed to create Admin: " + err.message);
    }
};

Handlers.handleDeleteUser = async (userId, email) => {
    if (!confirm(`Are you sure you want to delete user "${email}"?\n\nNote: This only removes them from the database. If they still exist in Firebase Auth, they can re-register.`)) {
        return;
    }

    try {
        await DB.deleteUser(userId);
        alert(`User "${email}" deleted successfully!`);
        State.navigate('admin-users'); // Refresh the list
    } catch (err) {
        alert("Failed to delete user: " + err.message);
    }
};

// ==========================================
// PUBLIC VERIFICATION HANDLERS (Two-Layer Verification)
// ==========================================

// State for public verification
Handlers.publicVerifyState = {
    originalCertificate: null,
    uploadedFileBase64: null,
    uploadedFileName: null
};

// Handle certificate lookup by ID
Handlers.handleCertificateLookup = async (e) => {
    e.preventDefault();

    const certId = document.getElementById('cert-lookup-id').value.trim().toUpperCase();
    const lookupBtn = document.getElementById('lookup-btn');
    const lookupResult = document.getElementById('lookup-result');
    const uploadSection = document.getElementById('upload-section');
    const verificationResults = document.getElementById('verification-results');

    if (!certId) {
        alert("Please enter a certificate number");
        return;
    }

    // Reset previous state
    Handlers.publicVerifyState.originalCertificate = null;
    uploadSection.style.display = 'none';
    verificationResults.style.display = 'none';

    // Show loading
    lookupBtn.innerHTML = '<i class="bx bx-loader-alt bx-spin"></i> Searching...';
    lookupBtn.disabled = true;

    try {
        // Search for certificate in Firestore
        const certificates = await DB.getAllCertificates();

        // Find by certificate number, register number, or ID
        const foundCert = certificates.find(cert =>
            (cert.registerNumber && cert.registerNumber.toUpperCase() === certId) ||
            (cert.certNumber && cert.certNumber.toUpperCase() === certId) ||
            (cert.id && cert.id.toUpperCase() === certId)
        );

        if (foundCert) {
            // Store the original certificate
            Handlers.publicVerifyState.originalCertificate = foundCert;

            // Show success result
            lookupResult.innerHTML = `
                <div style="padding: 1rem; background: rgba(34, 197, 94, 0.1); border: 1px solid var(--success); border-radius: 8px;">
                    <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                        <i class='bx bx-check-circle' style="color: var(--success); font-size: 1.25rem;"></i>
                        <strong style="color: var(--success);">Certificate Found!</strong>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; font-size: 0.9rem;">
                        <div>
                            <span style="color: var(--text-muted);">Certificate #:</span>
                            <strong>${foundCert.registerNumber || foundCert.certNumber || certId}</strong>
                        </div>
                        <div>
                            <span style="color: var(--text-muted);">Holder:</span>
                            <strong>${foundCert.name || foundCert.holderName || 'N/A'}</strong>
                        </div>
                        <div>
                            <span style="color: var(--text-muted);">Institution:</span>
                            <strong>${foundCert.institution || foundCert.organizer || 'N/A'}</strong>
                        </div>
                        <div>
                            <span style="color: var(--text-muted);">Status:</span>
                            <strong style="color: ${foundCert.status === 'approved' ? 'var(--success)' : 'var(--warning)'};">
                                ${foundCert.status ? foundCert.status.toUpperCase() : 'PENDING'}
                            </strong>
                        </div>
                    </div>
                </div>
            `;
            lookupResult.style.display = 'block';

            // Show upload section
            uploadSection.style.display = 'block';

        } else {
            // Show not found result
            lookupResult.innerHTML = `
                <div style="padding: 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 8px;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <i class='bx bx-x-circle' style="color: var(--danger); font-size: 1.25rem;"></i>
                        <strong style="color: var(--danger);">Certificate Not Found</strong>
                    </div>
                    <p style="margin: 0.5rem 0 0 0; color: var(--text-muted); font-size: 0.9rem;">
                        No certificate with ID "${certId}" was found in our database. 
                        Please check the certificate number and try again.
                    </p>
                </div>
            `;
            lookupResult.style.display = 'block';
            uploadSection.style.display = 'none';
        }

    } catch (error) {
        console.error("Certificate lookup error:", error);
        lookupResult.innerHTML = `
            <div style="padding: 1rem; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 8px;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <i class='bx bx-error' style="color: var(--danger); font-size: 1.25rem;"></i>
                    <strong style="color: var(--danger);">Lookup Error</strong>
                </div>
                <p style="margin: 0.5rem 0 0 0; color: var(--text-muted); font-size: 0.9rem;">
                    ${error.message}
                </p>
            </div>
        `;
        lookupResult.style.display = 'block';
    } finally {
        lookupBtn.innerHTML = '<i class="bx bx-search"></i> Lookup';
        lookupBtn.disabled = false;
    }
};

// Handle file selection for verification
Handlers.handleVerifyFileSelect = (input) => {
    if (input.files && input.files[0]) {
        const file = input.files[0];

        // Validate file size (max 5MB)
        if (file.size > 5 * 1024 * 1024) {
            alert("File too large! Maximum size is 5MB.");
            return;
        }

        // Read file as base64
        const reader = new FileReader();
        reader.onload = (e) => {
            Handlers.publicVerifyState.uploadedFileBase64 = e.target.result;
            Handlers.publicVerifyState.uploadedFileName = file.name;

            // Update UI
            document.getElementById('verify-upload-zone').style.display = 'none';
            document.getElementById('verify-file-preview').style.display = 'block';
            document.getElementById('verify-file-name').textContent = file.name;
            document.getElementById('verify-file-size').textContent = (file.size / 1024 / 1024).toFixed(2) + ' MB';
            document.getElementById('verify-btn').disabled = false;
        };
        reader.readAsDataURL(file);
    }
};

// Handle file drop for verification
Handlers.handleVerifyFileDrop = (e) => {
    e.preventDefault();
    e.target.classList.remove('dragover');

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        const fakeInput = { files: e.dataTransfer.files };
        Handlers.handleVerifyFileSelect(fakeInput);
    }
};

// Reset upload for verification
Handlers.resetVerifyUpload = () => {
    Handlers.publicVerifyState.uploadedFileBase64 = null;
    Handlers.publicVerifyState.uploadedFileName = null;

    document.getElementById('verify-upload-zone').style.display = 'block';
    document.getElementById('verify-file-preview').style.display = 'none';
    document.getElementById('verify-file-input').value = '';
    document.getElementById('verify-btn').disabled = true;
    document.getElementById('verification-results').style.display = 'none';
};

// Run the two-layer verification process
Handlers.runTwoLayerVerification = async () => {
    const verifyBtn = document.getElementById('verify-btn');
    const resultsSection = document.getElementById('verification-results');
    const reportContainer = document.getElementById('verification-report-container');

    const originalCert = Handlers.publicVerifyState.originalCertificate;
    const uploadedBase64 = Handlers.publicVerifyState.uploadedFileBase64;

    if (!originalCert) {
        alert("Please lookup a certificate first");
        return;
    }

    if (!uploadedBase64) {
        alert("Please upload a certificate file");
        return;
    }

    // Show loading state
    verifyBtn.innerHTML = '<i class="bx bx-loader-alt bx-spin"></i> Verifying...';
    verifyBtn.disabled = true;
    resultsSection.style.display = 'block';
    reportContainer.innerHTML = `
        <div style="text-align: center; padding: 2rem;">
            <div class="loader" style="margin: 0 auto 1rem auto;"></div>
            <p>Running Two-Layer Verification...</p>
            <p style="color: var(--text-muted); font-size: 0.85rem;">Layer 1: Hash Verification | Layer 2: OCR Field Comparison</p>
        </div>
    `;

    try {
        // Certificate data is stored in the 'data' property - get values from there
        const certData = originalCert.data || originalCert;

        console.log("[PublicVerify] Original certificate data:", certData);

        // Prepare original certificate data - extract from the nested data object
        const originalData = {
            file_hash_sha256: originalCert.fileHash || originalCert.hash || certData.fileHash || "",
            certificate_number: certData.registerNumber || certData.certNumber || originalCert.registerNumber || "",
            institution_name: certData.institution || certData.organizer || originalCert.institution || "",
            // The person's NAME is what we need to verify (this is what forgers would change)
            verified_certificate_name: certData.name || originalCert.name || ""
        };

        console.log("[PublicVerify] Prepared original data for comparison:", originalData);

        // Prepare uploaded certificate data
        const uploadedData = {
            file_binary: uploadedBase64,
            base64: uploadedBase64
        };

        let report;

        // Check if we have a stored hash for full verification
        if (originalData.file_hash_sha256) {
            // Full two-layer verification
            report = await CertificateVerifier.verify(originalData, uploadedData);
        } else {
            // OCR-only verification (no hash available)
            console.log("[PublicVerify] No stored hash found, running OCR-only verification");
            report = await CertificateVerifier.verifyWithoutHash(originalData, uploadedBase64);
        }

        // Generate and display the HTML report
        const htmlReport = CertificateVerifier.generateHTMLReport(report);
        reportContainer.innerHTML = htmlReport;

        // Log text report to console
        console.log(CertificateVerifier.generateTextReport(report));

    } catch (error) {
        console.error("Verification error:", error);
        reportContainer.innerHTML = `
            <div style="padding: 1.5rem; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 8px;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                    <i class='bx bx-error-circle' style="color: var(--danger); font-size: 1.5rem;"></i>
                    <h4 style="margin: 0; color: var(--danger);">Verification Failed</h4>
                </div>
                <p style="margin: 0; color: var(--text-muted);">
                    ${error.message}
                </p>
            </div>
        `;
    } finally {
        verifyBtn.innerHTML = '<i class="bx bx-shield-quarter"></i> Run Two-Layer Verification';
        verifyBtn.disabled = false;
    }
};

// Start
// Auth Persistence
auth.onAuthStateChanged(async firebaseUser => {
    if (firebaseUser) {
        // Parse Role from Display Name
        const [name, role] = (firebaseUser.displayName || "User|USER").split('|');

        // Fetch full user data from Firestore (includes register number)
        let registerNumber = '';
        try {
            const userData = await DB.getUser(firebaseUser.uid);
            if (userData && userData.registerNumber) {
                registerNumber = userData.registerNumber;
            }
        } catch (e) {
            console.warn("Could not fetch user data from Firestore:", e);
        }

        const user = {
            id: firebaseUser.uid,
            name: name,
            email: firebaseUser.email,
            registerNumber: registerNumber,
            role: role
        };
        console.log("Auth State: Logged In", user.email, "Register:", registerNumber);
        State.loginUser(user);
    } else {
        console.log("Auth State: Signed Out");
        State.navigate('login');
    }
});
