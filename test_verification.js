/**
 * CertValid Verification Unit Test Suite
 * Tests normalization, comparison rules, strict ID matching, and 3-state decisions
 */

// Import comparison logic
const Levenshtein = (str1, str2) => {
    const m = str1.length;
    const n = str2.length;
    const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            if (str1[i - 1] === str2[j - 1]) dp[i][j] = dp[i - 1][j - 1];
            else dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
        }
    }
    return dp[m][n];
};

const normalizeName = (name) => {
    if (!name) return "";
    return name
        .toString()
        .toUpperCase()
        .replace(/^(?:MR\.?|MS\.?|MRS\.?|MISS\.?|DR\.?|PROF\.?|SHRI\.?|SMT\.?|MX\.?|MASTER)\s+/i, '')
        .replace(/^(?:MR\.?\s*\/\s*MS\.?|MS\.?\s*\/\s*MR\.?)\s+/i, '')
        .replace(/[\.\,\;\:\'\"\_]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
};

const normalizeCertificateId = (id) => {
    if (!id) return "";
    return id.toString().toUpperCase().replace(/\s+/g, '').replace(/[\:\#]/g, '').trim();
};

const normalizeInstitution = (inst) => {
    if (!inst) return "";
    return inst.toString().toUpperCase().replace(/^(?:OF|FROM|AT|STUDENT OF)\s+/i, '').replace(/[\.\,\;\:\'\"\_\-\(\)]/g, ' ').replace(/\s+/g, ' ').trim();
};

const isFuzzyMatch = (str1, str2, fieldType = 'default') => {
    if (!str1 || !str2 || str1.toString().trim() === "" || str2.toString().trim() === "") {
        return false;
    }
    const s1 = str1.toString().trim();
    const s2 = str2.toString().trim();
    if (s1 === s2) return true;

    if (fieldType === 'number' || fieldType === 'certificate_number' || fieldType === 'certificateId') {
        const id1 = normalizeCertificateId(s1);
        const id2 = normalizeCertificateId(s2);
        if (id1 === id2) return true;
        const dist = Levenshtein(id1, id2);
        const maxLen = Math.max(id1.length, id2.length);
        const sim = maxLen === 0 ? 100 : ((maxLen - dist) / maxLen) * 100;
        return sim >= 92 && dist <= 1;
    }

    if (fieldType === 'name' || fieldType === 'verified_certificate_name') {
        const name1 = normalizeName(s1);
        const name2 = normalizeName(s2);
        if (name1 === name2) return true;
        const stripped1 = name1.replace(/\s/g, '');
        const stripped2 = name2.replace(/\s/g, '');
        if (stripped1 === stripped2) return true;
        const nameDist = Levenshtein(stripped1, stripped2);
        const nameMaxLen = Math.max(stripped1.length, stripped2.length);
        const nameSim = nameMaxLen === 0 ? 100 : ((nameMaxLen - nameDist) / nameMaxLen) * 100;
        return nameSim >= 78;
    }

    const norm1 = normalizeInstitution(s1);
    const norm2 = normalizeInstitution(s2);
    if (norm1 === norm2) return true;
    const distance = Levenshtein(norm1, norm2);
    const maxLen = Math.max(norm1.length, norm2.length);
    const similarity = maxLen === 0 ? 100 : ((maxLen - distance) / maxLen) * 100;
    return similarity >= 75;
};

const compareFields = (originalData, extractedData) => {
    const fields = {
        certificate_number: {
            original: originalData.certificateNumber || originalData.registerNumber || "",
            extracted: extractedData.certificateNumber || extractedData.registerNumber || extractedData.certificateId || "",
            status: "Pending"
        },
        institution_name: {
            original: originalData.institutionName || originalData.institution || "",
            extracted: extractedData.institutionName || extractedData.institution || "",
            status: "Pending"
        },
        verified_certificate_name: {
            original: originalData.name || originalData.recipientName || "",
            extracted: extractedData.name || extractedData.recipientName || "",
            status: "Pending"
        }
    };

    let editedFields = [];
    let missingFields = [];

    for (const fieldName of Object.keys(fields)) {
        const field = fields[fieldName];
        const orig = field.original || "";
        const extr = field.extracted || "";

        if (!extr || extr.trim() === "") {
            field.status = "Missing";
            missingFields.push(fieldName);
            editedFields.push(fieldName);
            continue;
        }

        const isMatch = isFuzzyMatch(orig, extr, fieldName);
        if (!isMatch) {
            field.status = "Mismatch";
            editedFields.push(fieldName);
        } else {
            field.status = "Match";
        }
    }

    const hasKeyExtraction = Boolean(fields.verified_certificate_name.extracted && fields.verified_certificate_name.extracted.length > 1) ||
                             Boolean(fields.certificate_number.extracted && fields.certificate_number.extracted.length > 1);
    const unableToVerify = !hasKeyExtraction || (missingFields.length >= 2);

    let finalResult = "PENDING";
    if (unableToVerify) finalResult = "UNABLE TO VERIFY";
    else if (editedFields.length === 0) finalResult = "VALID";
    else if (editedFields.length >= 2) finalResult = "FAKE";
    else finalResult = "EDITED";

    return { fields, editedFields, unableToVerify, finalResult };
};

// ==========================================
// TEST CASES
// ==========================================

console.log("==================================================");
console.log("🧪 RUNNING CERTTVALID VERIFICATION TESTS");
console.log("==================================================");

let passed = 0;
let total = 0;

function assertTest(name, expected, actual) {
    total++;
    const ok = expected === actual;
    if (ok) {
        console.log(`✅ [PASS] ${name} -> Expected: ${expected}, Got: ${actual}`);
        passed++;
    } else {
        console.error(`❌ [FAIL] ${name} -> Expected: ${expected}, Got: ${actual}`);
    }
}

const storedCert = {
    name: "AKSHAY ANAND M P",
    registerNumber: "CERT-2026-001",
    institution: "Dr. N.G.P. Institute of Technology",
    course: "Full Stack Development"
};

// Test 1: Clear matching certificate
const t1 = compareFields(storedCert, {
    name: "AKSHAY ANAND M P",
    certificateId: "CERT-2026-001",
    institution: "Dr. N.G.P. Institute of Technology"
});
assertTest("Test 1: Clear matching certificate", "VALID", t1.finalResult);

// Test 2: Different font & minor spacing / dots
const t2 = compareFields(storedCert, {
    name: "Akshay Anand M.P.",
    certificateId: "CERT-2026-001",
    institution: "Dr. N.G.P. Institute of Technology"
});
assertTest("Test 2: Different font/casing (Akshay Anand M.P.)", "VALID", t2.finalResult);

// Test 3: Modified name (fraudulent edit)
const t3 = compareFields(storedCert, {
    name: "RAHUL KUMAR",
    certificateId: "CERT-2026-001",
    institution: "Dr. N.G.P. Institute of Technology"
});
assertTest("Test 3: Modified recipient name (RAHUL KUMAR)", "EDITED", t3.finalResult);

// Test 4: Modified certificate ID (Strict check)
const t4 = compareFields(storedCert, {
    name: "AKSHAY ANAND M P",
    certificateId: "CERT-2026-999",
    institution: "Dr. N.G.P. Institute of Technology"
});
assertTest("Test 4: Modified certificate ID (CERT-2026-999)", "EDITED", t4.finalResult);

// Test 5: Completely different certificate
const t5 = compareFields(storedCert, {
    name: "CHANDRU T",
    certificateId: "CERT-9999-888",
    institution: "PSG College of Technology"
});
assertTest("Test 5: Completely different certificate", "FAKE", t5.finalResult);

// Test 6: Empty OCR output (Important Bug Fix check)
const t6 = compareFields(storedCert, {
    name: "",
    certificateId: "",
    institution: ""
});
assertTest("Test 6: Empty OCR output must be UNABLE TO VERIFY", "UNABLE TO VERIFY", t6.finalResult);

// Test 7: Missing name and ID
const t7 = compareFields(storedCert, {
    name: "",
    certificateId: "",
    institution: "Dr. N.G.P. Institute of Technology"
});
assertTest("Test 7: Unreadable name and ID", "UNABLE TO VERIFY", t7.finalResult);

console.log("==================================================");
console.log(`📊 Test Summary: ${passed}/${total} passed`);
console.log("==================================================");

if (passed === total) {
    process.exit(0);
} else {
    process.exit(1);
}
