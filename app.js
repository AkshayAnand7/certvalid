


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
            const provider = new ethers.providers.Web3Provider(window.ethereum);
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
        console.log(`[OCR] Analyzing image...`);

        // Configuration - Update this URL for production deployment
        const PADDLE_OCR_URL = 'http://localhost:5000/ocr';

        // Try PaddleOCR Backend First
        try {
            console.log("[OCR] Trying PaddleOCR backend...");

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout for large PDFs

            const response = await fetch(PADDLE_OCR_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ image: imageInput }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                const result = await response.json();
                console.log("[OCR] PaddleOCR Success:", result);

                // Check if there's an error in the response
                if (result.error) {
                    console.warn("[OCR] Backend returned error:", result.error);
                    throw new Error(result.error);
                }

                if (!result.name && !result.degree) {
                    alert("OCR finished but some fields are missing. Please manually enter/correct the details.");
                }

                return {
                    name: result.name || "",
                    registerNumber: result.registerNumber || "",
                    institution: result.institution || "",
                    degree: result.degree || "",
                    year: result.year || new Date().getFullYear().toString(),
                    gpa: result.gpa || ""
                };
            } else {
                const errorText = await response.text();
                console.warn("[OCR] Backend error response:", response.status, errorText);
                throw new Error(`Server error: ${response.status}`);
            }
        } catch (err) {
            console.warn("[OCR] PaddleOCR backend unavailable, falling back to Tesseract.js:", err.message);
        }

        // Fallback to Tesseract.js
        console.log("[OCR] Using Tesseract.js fallback...");

        if (!window.Tesseract) {
            console.warn("Tesseract.js not loaded. Please check internet connection.");
            return { name: "", registerNumber: "", institution: "", degree: "" };
        }

        try {
            // Tesseract.js Worker
            const { data: { text } } = await Tesseract.recognize(
                imageInput,
                'eng',
                { logger: m => console.log(`[OCR] ${m.status}: ${Math.round(m.progress * 100)}%`) }
            );

            console.log("OCR Raw Text:", text);
            const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 2);

            // Helper: Find line containing keyword and strip label
            const extractField = (keywords) => {
                const line = lines.find(l => keywords.some(k => l.toLowerCase().includes(k)));
                if (!line) return "";
                // Remove label (e.g., "Name: John" -> "John")
                return line.replace(new RegExp(`^.*(${keywords.join('|')})[^:]*:?\\s*`, 'i'), '').trim();
            };

            // Heuristic Parsing
            const name = extractField(['name', 'student']);
            const reg = extractField(['register', 'reg no', 'id number', 'enrollment']);
            const inst = extractField(['institution', 'university', 'college', 'institute']);
            const degree = extractField(['degree', 'bachelor', 'master', 'outcome', 'programme']);

            // If empty, user will fill it.
            const result = {
                name: name || "",
                registerNumber: reg || "",
                institution: inst || "",
                degree: degree || "",
                year: new Date().getFullYear().toString(),
                gpa: ""
            };

            if (!name || !degree) {
                alert("OCR finished but some fields are missing. Please manually enter/correct the details.");
            }

            return result;

        } catch (err) {
            console.error("OCR Error:", err);
            alert("OCR Failed: " + (err.message || "Unknown Error") + "\n\nPlease manually enter the correct details in the form.");
            return { name: "", registerNumber: "", institution: "", degree: "" };
        }
    }
};


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
                    <div class="input-group">
                        <label class="input-label">Email Address</label>
                        <input type="email" name="email" class="input-field" placeholder="name@example.com" required>
                    </div>
                    <div class="input-group">
                        <label class="input-label">Password</label>
                        <input type="password" name="password" class="input-field" placeholder="••••••••" required>
                    </div>
                    <div style="text-align: right; margin-bottom: 1rem;">
                        <a href="#" onclick="Handlers.handleForgotPassword()" style="font-size: 0.8rem; color: var(--text-muted);">Forgot Password?</a>
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

        try {
            const user = await API.login(email, pass);
            if (user) {
                State.loginUser(user);
            } else {
                alert('Invalid credentials');
            }
        } catch (err) {
            console.error(err);
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

    handleForgotPassword: async () => {
        const email = prompt("Enter your registered email address:");
        if (!email) return;

        try {
            await API.forgotPassword(email);
            alert(`Password Reset Email sent to ${email}`);
        } catch (err) {
            alert("Error: " + err.message);
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
                        ${Views.verifierSearch()}
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
