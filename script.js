// ======================================================
// PASSWORD SECURITY ANALYZER V3
// ======================================================

// ======================================================
// GET HTML ELEMENTS
// ======================================================

const passwordInput = document.getElementById("password");
const strengthElement = document.getElementById("strength");
const scoreElement = document.getElementById("score");
const scoreRing = document.getElementById("score-ring");
const progressBar = document.getElementById("progress-bar");

const lengthRequirement = document.getElementById("length-requirement");
const uppercaseRequirement = document.getElementById("uppercase-requirement");
const lowercaseRequirement = document.getElementById("lowercase-requirement");
const numberRequirement = document.getElementById("number-requirement");
const specialRequirement = document.getElementById("special-requirement");

const togglePasswordButton = document.getElementById("toggle-password");
const copyPasswordButton = document.getElementById("copy-password");
const copyStatus = document.getElementById("copy-status");
const checkRockyouButton = document.getElementById("check-rockyou");
const checkHibpButton = document.getElementById("check-hibp");

const wordlistStatus = document.getElementById("wordlist-status");
const hibpStatus = document.getElementById("hibp-status");

const repeatedCharacterPattern = document.getElementById("repeated-character-pattern");
const repeatedCharacterMessage = document.getElementById("repeated-character-message");
const sequentialPattern = document.getElementById("sequential-pattern");
const sequentialMessage = document.getElementById("sequential-message");
const repeatedPattern = document.getElementById("repeated-pattern");
const repeatedPatternMessage = document.getElementById("repeated-pattern-message");

// const entropyValue = document.getElementById("entropy-value");
// const entropyBar = document.getElementById("entropy-bar");
// const entropyDescription = document.getElementById("entropy-description");

const searchSpaceElement = document.getElementById("search-space");
const gpuRateElement = document.getElementById("gpu-rate");
const timeAverageElement = document.getElementById("time-average");
const timeWorstElement = document.getElementById("time-worst");

const generatorLength = document.getElementById("generator-length");
const generatorLengthNumber = document.getElementById("generator-length-number");
const generatorLengthValue = document.getElementById("generator-length-value");
const genUppercase = document.getElementById("gen-uppercase");
const genLowercase = document.getElementById("gen-lowercase");
const genNumbers = document.getElementById("gen-numbers");
const genSpecial = document.getElementById("gen-special");
const generatePasswordButton = document.getElementById("generate-password");
const generatorStatus = document.getElementById("generator-status");
const generatedPasswordInput = document.getElementById("generated-password");
const copyGeneratedPasswordButton = document.getElementById("copy-generated-password");
const useGeneratedPasswordButton = document.getElementById("use-generated-password");
const generatedCopyStatus = document.getElementById("generated-copy-status");


// ======================================================
// CONFIGURATION
// ======================================================

const CHARACTER_SETS = {
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    numbers: "0123456789",
    special: "!@#$%^&*()-_=+[]{};:,.?"
};

// These are assumptions for a theoretical crack-time display.
// They are not universal attacker speeds.
const GUESS_RATES = {
    online: 100,
    slowHash: 100000,
    fastHash: 10000000000
};

let rockyouPasswords = [];
let rockyouLoaded = false;


// ======================================================
// BASIC CHARACTER CHECKS
// ======================================================

function hasUppercase(password) {
    return /[A-Z]/.test(password);
}

function hasLowercase(password) {
    return /[a-z]/.test(password);
}

function hasNumber(password) {
    return /[0-9]/.test(password);
}

function hasSpecialCharacter(password) {
    return /[^A-Za-z0-9]/.test(password);
}


// ======================================================
// SCORE
// ======================================================

function calculateLengthScore(password) {

    const length = password.length;

    if (length >= 20) {
        return 20;
    }

    if (length >= 12) {
        return 15;
    }

    if (length >= 8) {
        return 10;
    }

    return 0;
}

function calculateCharacterScore(password, pattern) {

    const matches = password.match(pattern);
    let count = 0;

    if (matches) {
        count = matches.length;
    }

    if (count >= 3) {
        return 20;
    }

    if (count === 2) {
        return 15;
    }

    if (count === 1) {
        return 7;
    }

    return 0;
}

function calculateStrength(password) {

    const lengthScore = calculateLengthScore(password);

    const uppercaseScore = calculateCharacterScore(password, /[A-Z]/g);
    const lowercaseScore = calculateCharacterScore(password, /[a-z]/g);
    const numberScore = calculateCharacterScore(password, /[0-9]/g);
    const specialScore = calculateCharacterScore(password, /[^A-Za-z0-9]/g);

    return (
        lengthScore +
        uppercaseScore +
        lowercaseScore +
        numberScore +
        specialScore
    );
}

function updateRequirement(element, valid) {

    const icon = element.querySelector(".requirement-icon");

    if (valid) {
        element.classList.add("valid");
        element.classList.remove("invalid");
        icon.textContent = "✓";
    }
    else {
        element.classList.add("invalid");
        element.classList.remove("valid");
        icon.textContent = "✗";
    }
}

function updateStrength(score) {
    let strengthColor = "#e27676";

    if (score < 50) {
        strengthElement.textContent = "Very Weak";
        strengthElement.className = "very-weak";
        strengthColor = "#e27676";
    }
    else if (score < 60) {
        strengthElement.textContent = "Weak";
        strengthElement.className = "weak";
        strengthColor = "#e89b62";
    }
    else if (score < 70) {
        strengthElement.textContent = "Medium";
        strengthElement.className = "medium";
        strengthColor = "#e0c66c";
    }
    else if (score < 90) {
        strengthElement.textContent = "Strong";
        strengthElement.className = "strong";
        strengthColor = "#6dd8a1";
    }
    else {
        strengthElement.textContent = "Very Strong";
        strengthElement.className = "very-strong";
        strengthColor = "#6dd8a1";
    }

    progressBar.style.backgroundColor = strengthColor;
    scoreRing.style.setProperty("--score", score + "%");
    scoreRing.style.setProperty("--score-color", strengthColor);
    scoreElement.style.color = strengthColor;
    strengthElement.style.color = strengthColor;
}


// ======================================================
// WEAK PATTERN DETECTION
// ======================================================

function detectRepeatedCharacters(password) {

    if (password.length < 3) {
        return null;
    }

    let count = 1;

    for (let i = 1; i < password.length; i++) {

        if (password[i] === password[i - 1]) {
            count++;

            if (count >= 3) {
                const start = i - count + 1;

                return {
                    detected: true,
                    pattern: password.substring(start, i + 1),
                    length: count
                };
            }
        }
        else {
            count = 1;
        }
    }

    return null;
}

function isConstantStepSequence(text) {

    if (text.length < 3) {
        return false;
    }

    const first = text.charCodeAt(0);
    const second = text.charCodeAt(1);
    const step = second - first;

    if (step === 0) {
        return false;
    }

    for (let i = 2; i < text.length; i++) {

        const current = text.charCodeAt(i);
        const previous = text.charCodeAt(i - 1);

        if (current - previous !== step) {
            return false;
        }
    }

    return true;
}

function getSequenceType(text) {

    let numeric = true;
    let alphabetic = true;

    for (let i = 0; i < text.length; i++) {

        if (!/[0-9]/.test(text[i])) {
            numeric = false;
        }

        if (!/[a-zA-Z]/.test(text[i])) {
            alphabetic = false;
        }
    }

    if (numeric) {
        return "Numeric sequence";
    }

    if (alphabetic) {
        return "Alphabetic sequence";
    }

    return "Character sequence";
}

const keyboardRows = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm"
];

function detectKeyboardSequence(password) {

    const lowerPassword = password.toLowerCase();

    for (let rowIndex = 0; rowIndex < keyboardRows.length; rowIndex++) {

        const row = keyboardRows[rowIndex];

        for (let start = 0; start < row.length - 2; start++) {

            for (let end = start + 3; end <= row.length; end++) {

                const sequence = row.substring(start, end);
                const reversedSequence = sequence.split("").reverse().join("");

                if (lowerPassword.includes(sequence)) {
                    return {
                        detected: true,
                        pattern: sequence,
                        type: "Keyboard sequence"
                    };
                }

                if (lowerPassword.includes(reversedSequence)) {
                    return {
                        detected: true,
                        pattern: reversedSequence,
                        type: "Keyboard sequence"
                    };
                }
            }
        }
    }

    return null;
}

function detectSequentialPatterns(password) {

    if (password.length < 3) {
        return null;
    }

    const keyboardResult = detectKeyboardSequence(password);

    if (keyboardResult) {
        return keyboardResult;
    }

    let bestResult = null;

    for (let start = 0; start < password.length - 2; start++) {

        for (let end = start + 3; end <= password.length; end++) {

            const section = password.substring(start, end);

            if (isConstantStepSequence(section)) {

                const result = {
                    detected: true,
                    pattern: section,
                    length: section.length,
                    type: getSequenceType(section)
                };

                if (bestResult === null || result.length > bestResult.length) {
                    bestResult = result;
                }
            }
        }
    }

    return bestResult;
}

function detectRepeatedPattern(password) {

    if (password.length < 4) {
        return null;
    }

    let bestResult = null;

    for (let start = 0; start < password.length - 3; start++) {

        for (
            let patternLength = 1;
            patternLength <= Math.floor((password.length - start) / 2);
            patternLength++
        ) {

            const pattern = password.substring(start, start + patternLength);
            let repetitions = 1;
            let position = start + patternLength;

            while (position + patternLength <= password.length) {

                const current = password.substring(
                    position,
                    position + patternLength
                );

                if (current === pattern) {
                    repetitions++;
                    position += patternLength;
                }
                else {
                    break;
                }
            }

            if (repetitions >= 2) {

                const repeatedLength = repetitions * patternLength;

                if (repeatedLength >= 4) {

                    const result = {
                        detected: true,
                        pattern: pattern,
                        repetitions: repetitions,
                        length: repeatedLength,
                        start: start
                    };

                    if (bestResult === null) {
                        bestResult = result;
                    }
                    else if (result.length > bestResult.length) {
                        bestResult = result;
                    }
                    else if (
                        result.length === bestResult.length &&
                        result.pattern.length < bestResult.pattern.length
                    ) {
                        bestResult = result;
                    }
                }
            }
        }
    }

    return bestResult;
}

function updateWeakPatterns(password) {

    const repeatedCharacters = detectRepeatedCharacters(password);

    if (repeatedCharacters) {
        repeatedCharacterPattern.className = "pattern-item pattern-warning";
        repeatedCharacterPattern.querySelector(".pattern-icon").textContent = "⚠";
        repeatedCharacterMessage.textContent =
            "Repeated characters detected: '" + repeatedCharacters.pattern + "'";
    }
    else {
        repeatedCharacterPattern.className = "pattern-item pattern-safe";
        repeatedCharacterPattern.querySelector(".pattern-icon").textContent = "✓";
        repeatedCharacterMessage.textContent = "No repeated characters detected.";
    }

    const sequential = detectSequentialPatterns(password);

    if (sequential) {
        sequentialPattern.className = "pattern-item pattern-warning";
        sequentialPattern.querySelector(".pattern-icon").textContent = "⚠";
        sequentialMessage.textContent =
            sequential.type + " detected: '" + sequential.pattern + "'";
    }
    else {
        sequentialPattern.className = "pattern-item pattern-safe";
        sequentialPattern.querySelector(".pattern-icon").textContent = "✓";
        sequentialMessage.textContent = "No sequential pattern detected.";
    }

    const repeated = detectRepeatedPattern(password);

    if (repeated) {
        repeatedPattern.className = "pattern-item pattern-warning";
        repeatedPattern.querySelector(".pattern-icon").textContent = "⚠";
        repeatedPatternMessage.textContent =
            "Repeated pattern detected: '" +
            repeated.pattern +
            "' × " +
            repeated.repetitions;
    }
    else {
        repeatedPattern.className = "pattern-item pattern-safe";
        repeatedPattern.querySelector(".pattern-icon").textContent = "✓";
        repeatedPatternMessage.textContent = "No repeated pattern detected.";
    }
}


// ======================================================
// CRACK-TIME ESTIMATION
// ======================================================

function formatDuration(seconds) {

    if (!Number.isFinite(seconds)) {
        return "Effectively unlimited";
    }

    if (seconds < 1) {
        return "Less than 1 second";
    }

    const minute = 60;
    const hour = minute * 60;
    const day = hour * 24;
    const year = day * 365;

    if (seconds < minute) {
        return Math.max(1, Math.round(seconds)) + " seconds";
    }

    if (seconds < hour) {
        return Math.round(seconds / minute) + " minutes";
    }

    if (seconds < day) {
        return Math.round(seconds / hour) + " hours";
    }

    if (seconds < year) {
        return Math.round(seconds / day) + " days";
    }

    if (seconds < year * 1000) {
        return formatLargeNumber(seconds / year, "year");
    }

    if (seconds < year * 1000000) {
        return formatLargeNumber(seconds / year, "year");
    }

    return formatScientificYears(seconds / year);
}

function formatLargeNumber(value, unit) {

    if (value < 1000) {
        return Math.round(value) + " " + unit + (Math.round(value) === 1 ? "" : "s");
    }

    return value.toExponential(2) + " " + unit + "s";
}

function formatScientificYears(years) {
    return years.toExponential(2) + " years";
}

function secondsFromEntropy(entropy, guessesPerSecond) {

    if (entropy <= 0) {
        return 0;
    }

    // Average-case search is half the full key space.
    const log2Seconds = entropy - 1 - Math.log2(guessesPerSecond);

    if (log2Seconds > 1023) {
        return Infinity;
    }

    return Math.pow(2, log2Seconds);
}

function getCharacterPoolSize(password) {

    let poolSize = 0;

    if (/[a-z]/.test(password)) {
        poolSize += 26;
    }

    if (/[A-Z]/.test(password)) {
        poolSize += 26;
    }

    if (/[0-9]/.test(password)) {
        poolSize += 10;
    }

    if (/[^A-Za-z0-9]/.test(password)) {
        poolSize += 32;
    }

    return poolSize;
}


function formatNumber(value) {

    if (!Number.isFinite(value)) {
        return "Too large";
    }

    return new Intl.NumberFormat("en-US").format(value);
}


function formatCrackDuration(seconds) {

    if (!Number.isFinite(seconds)) {
        return "Too large";
    }

    const minute = 60;
    const hour = 60 * minute;
    const day = 24 * hour;
    const month = 30.44 * day;
    const year = 365.25 * day;

    if (seconds < 1) {
        return seconds.toFixed(3) + " seconds";
    }

    if (seconds < minute) {
        return seconds.toFixed(1) + " seconds";
    }

    if (seconds < hour) {
        return (seconds / minute).toFixed(1) + " minutes";
    }

    if (seconds < day) {
        return (seconds / hour).toFixed(1) + " hours";
    }

    if (seconds < month) {
        return (seconds / day).toFixed(1) + " days";
    }

    if (seconds < year) {
        return (seconds / month).toFixed(1) + " months";
    }

    return (seconds / year).toFixed(1) + " years";
}


function calculateSearchSpace(password) {

    const length = password.length;
    const poolSize = getCharacterPoolSize(password);

    if (length === 0 || poolSize === 0) {
        return 0;
    }

    const log10SearchSpace =
        length * Math.log10(poolSize);

    if (log10SearchSpace > 308) {
        return Infinity;
    }

    return Math.pow(poolSize, length);
}


// Crack-time values are theoretical and depend on the hashing/cracking
// protocol assumed by this project and its configured guesses-per-second rate.
function updateCrackTime() {

    const password = passwordInput.value;

    if (password.length === 0) {
        if (searchSpaceElement) {
            searchSpaceElement.textContent = "—";
        }
        gpuRateElement.textContent = "255,000 guesses/sec";
        timeAverageElement.textContent = "—";
        timeWorstElement.textContent = "—";
        return;
    }

    const searchSpace = calculateSearchSpace(password);
    const guessesPerSecond = 255000;

    if (searchSpaceElement) {
        searchSpaceElement.textContent = formatNumber(searchSpace);
    }

    gpuRateElement.textContent =
        "255,000 guesses/sec";

    if (!Number.isFinite(searchSpace)) {
        timeAverageElement.textContent = "Too large";
        timeWorstElement.textContent = "Too large";
        return;
    }

    const worstCaseSeconds =
        searchSpace / guessesPerSecond;

    const averageCaseSeconds =
        worstCaseSeconds / 2;

    timeAverageElement.textContent =
        formatCrackDuration(averageCaseSeconds);

    timeWorstElement.textContent =
        formatCrackDuration(worstCaseSeconds);
}

// ======================================================
// ROCKYOU
// ======================================================

async function loadRockyouWordlist() {

    try {
        const response = await fetch("Wordlists/rockyou.txt");

        if (!response.ok) {
            throw new Error("Unable to load rockyou.txt");
        }

        const data = await response.text();

        rockyouPasswords = data
            .split(/\r?\n/)
            .map(function (password) {
                return password.trim();
            })
            .filter(function (password) {
                return password.length > 0;
            });

        rockyouLoaded = rockyouPasswords.length > 0;

        if (rockyouLoaded) {
            wordlistStatus.textContent = "RockYou loaded. Ready for local check.";
            wordlistStatus.className = "wordlist-safe";
        }
        else {
            wordlistStatus.textContent = "Unable to load rockyou.txt.";
            wordlistStatus.className = "wordlist-warning";
        }
    }
    catch (error) {
        rockyouLoaded = false;
        wordlistStatus.textContent = "RockYou could not be loaded.";
        wordlistStatus.className = "wordlist-warning";
    }
}

function checkRockyou(password) {

    if (password.length === 0) {
        return;
    }

    if (!rockyouLoaded) {
        wordlistStatus.textContent = "RockYou wordlist is not available.";
        wordlistStatus.className = "wordlist-warning";
        return;
    }

    if (rockyouPasswords.includes(password)) {
        wordlistStatus.textContent = "⚠ Password found in rockyou.txt";
        wordlistStatus.className = "wordlist-warning";
    }
    else {
        wordlistStatus.textContent = "✓ Password not found in rockyou.txt";
        wordlistStatus.className = "wordlist-safe";
    }
}


// ======================================================
// HIBP PWNED PASSWORDS API
// ======================================================

async function sha1Hex(text) {

    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    return hashArray
        .map(function (byte) {
            return byte.toString(16).padStart(2, "0");
        })
        .join("")
        .toUpperCase();
}

async function checkPwnedPassword(password) {

    if (password.length === 0) {
        return;
    }

    checkHibpButton.disabled = true;
    checkHibpButton.textContent = "Checking...";
    hibpStatus.textContent = "Checking breach database...";
    hibpStatus.className = "result-value";

    try {
        const fullHash = await sha1Hex(password);
        const prefix = fullHash.substring(0, 5);
        const suffix = fullHash.substring(5);

        const response = await fetch(
            "https://api.pwnedpasswords.com/range/" + prefix
        );

        if (!response.ok) {
            throw new Error("HIBP request failed");
        }

        const data = await response.text();
        const lines = data.split(/\r?\n/);
        let matchCount = 0;

        for (let i = 0; i < lines.length; i++) {

            const line = lines[i].trim();

            if (line.length === 0) {
                continue;
            }

            const parts = line.split(":");
            const returnedSuffix = parts[0];
            const count = Number(parts[1]);

            if (returnedSuffix === suffix) {
                matchCount = count;
                break;
            }
        }

        if (matchCount > 0) {
            hibpStatus.textContent =
                "⚠ Compromised — seen " + matchCount.toLocaleString() + " times";
            hibpStatus.className = "hibp-warning";
        }
        else {
            hibpStatus.textContent =
                "✓ No match found in the Pwned Passwords corpus";
            hibpStatus.className = "hibp-safe";
        }
    }
    catch (error) {
        hibpStatus.textContent =
            "Unable to complete the breach check. Try again later.";
        hibpStatus.className = "hibp-warning";
    }
    finally {
        checkHibpButton.disabled = false;
        checkHibpButton.textContent = "🌐 Check Breach Database";
    }
}


// ======================================================
// SECURE PASSWORD GENERATOR
// ======================================================

function secureRandomIndex(max) {

    if (max <= 0) {
        throw new Error("Invalid character set length");
    }

    const limit = Math.floor(256 / max) * max;
    const randomByte = new Uint8Array(1);

    do {
        crypto.getRandomValues(randomByte);
    }
    while (randomByte[0] >= limit);

    return randomByte[0] % max;
}

function secureRandomCharacter(characters) {
    const index = secureRandomIndex(characters.length);
    return characters[index];
}

function shuffleSecurely(array) {

    for (let i = array.length - 1; i > 0; i--) {

        const randomIndex = secureRandomIndex(i + 1);
        const temporary = array[i];

        array[i] = array[randomIndex];
        array[randomIndex] = temporary;
    }

    return array;
}

function getGeneratorCharacterSets() {

    const sets = [];

    if (genUppercase.checked) {
        sets.push(CHARACTER_SETS.uppercase);
    }

    if (genLowercase.checked) {
        sets.push(CHARACTER_SETS.lowercase);
    }

    if (genNumbers.checked) {
        sets.push(CHARACTER_SETS.numbers);
    }

    if (genSpecial.checked) {
        sets.push(CHARACTER_SETS.special);
    }

    return sets;
}

function generateSecurePassword() {

    const length = Number(generatorLengthNumber.value);
    const sets = getGeneratorCharacterSets();

    if (length < 4 || length > 64) {
        generatorStatus.textContent = "Length must be between 4 and 64.";
        return;
    }

    if (sets.length === 0) {
        generatorStatus.textContent = "Select at least one character type.";
        return;
    }

    if (length < sets.length) {
        generatorStatus.textContent =
            "The selected length must be at least " + sets.length + " characters.";
        return;
    }

    const allCharacters = sets.join("");
    const passwordCharacters = [];

    // Guarantee at least one character from every selected category.
    for (let i = 0; i < sets.length; i++) {
        passwordCharacters.push(
            secureRandomCharacter(sets[i])
        );
    }

    while (passwordCharacters.length < length) {
        passwordCharacters.push(
            secureRandomCharacter(allCharacters)
        );
    }

    shuffleSecurely(passwordCharacters);

    const generatedPasswordValue = passwordCharacters.join("");

    generatedPasswordInput.value = generatedPasswordValue;
    copyGeneratedPasswordButton.disabled = false;
    useGeneratedPasswordButton.disabled = false;
    generatedCopyStatus.textContent = "";
    generatorStatus.textContent = "✓ Secure password generated locally with Web Crypto.";
}

function syncGeneratorLength(value) {

    let length = Number(value);

    if (length < 4) {
        length = 4;
    }

    if (length > 64) {
        length = 64;
    }

    generatorLength.value = length;
    generatorLengthNumber.value = length;
    generatorLengthValue.textContent = length;
}


// ======================================================
// ANALYZE PASSWORD
// ======================================================

function resetAnalysis() {

    strengthElement.textContent = "Not analyzed";
    strengthElement.className = "";
    scoreElement.textContent = "0%";
    scoreElement.style.color = "#e27676";
    strengthElement.style.color = "#e27676";
    scoreRing.style.setProperty("--score", "0%");
    scoreRing.style.setProperty("--score-color", "#e27676");
    progressBar.style.width = "0%";
    progressBar.style.backgroundColor = "#e27676";

    updateCrackTime();

    copyPasswordButton.disabled = true;
    checkRockyouButton.disabled = true;
    checkHibpButton.disabled = true;

    wordlistStatus.textContent = "Not checked";
    wordlistStatus.className = "result-value";

    hibpStatus.textContent = "Not checked";
    hibpStatus.className = "result-value";

    repeatedCharacterPattern.className = "pattern-item pattern-safe";
    sequentialPattern.className = "pattern-item pattern-safe";
    repeatedPattern.className = "pattern-item pattern-safe";

    repeatedCharacterPattern.querySelector(".pattern-icon").textContent = "✓";
    sequentialPattern.querySelector(".pattern-icon").textContent = "✓";
    repeatedPattern.querySelector(".pattern-icon").textContent = "✓";

    repeatedCharacterMessage.textContent = "No repeated characters detected.";
    sequentialMessage.textContent = "No sequential pattern detected.";
    repeatedPatternMessage.textContent = "No repeated pattern detected.";
}

function analyzePassword() {

    const password = passwordInput.value;

    const lengthValid = password.length >= 8;
    const uppercaseValid = hasUppercase(password);
    const lowercaseValid = hasLowercase(password);
    const numberValid = hasNumber(password);
    const specialValid = hasSpecialCharacter(password);

    updateRequirement(lengthRequirement, lengthValid);
    updateRequirement(uppercaseRequirement, uppercaseValid);
    updateRequirement(lowercaseRequirement, lowercaseValid);
    updateRequirement(numberRequirement, numberValid);
    updateRequirement(specialRequirement, specialValid);

    if (password.length === 0) {
        resetAnalysis();
        return;
    }

    copyPasswordButton.disabled = false;
    checkRockyouButton.disabled = false;
    checkHibpButton.disabled = false;

    const score = calculateStrength(password);

    scoreElement.textContent = score + "%";
    progressBar.style.width = score + "%";

    updateStrength(score);
    updateWeakPatterns(password);
    updateCrackTime();

    // These checks stay manual to avoid loading or querying large resources
    // on every keystroke.
    wordlistStatus.textContent = "Ready — click Check RockYou";
    wordlistStatus.className = "result-value";

    hibpStatus.textContent = "Ready — click Check Breach Database";
    hibpStatus.className = "result-value";
}


// ======================================================
// EVENT LISTENERS
// ======================================================

passwordInput.addEventListener("input", function () {
    analyzePassword();
});

togglePasswordButton.addEventListener("click", function () {

    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        togglePasswordButton.textContent = "🙈";
        togglePasswordButton.title = "Hide password";
    }
    else {
        passwordInput.type = "password";
        togglePasswordButton.textContent = "👁️";
        togglePasswordButton.title = "Show password";
    }
});

copyPasswordButton.addEventListener("click", async function () {

    const password = passwordInput.value;

    if (password.length === 0) {
        return;
    }

    try {
        await navigator.clipboard.writeText(password);
        copyStatus.textContent = "✓ Password copied";

        setTimeout(function () {
            copyStatus.textContent = "";
        }, 2000);
    }
    catch (error) {
        copyStatus.textContent = "Unable to copy password.";
    }
});

checkRockyouButton.addEventListener("click", function () {
    checkRockyou(passwordInput.value);
});

checkHibpButton.addEventListener("click", function () {
    checkPwnedPassword(passwordInput.value);
});

generatorLength.addEventListener("input", function () {
    syncGeneratorLength(generatorLength.value);
});

generatorLengthNumber.addEventListener("input", function () {
    syncGeneratorLength(generatorLengthNumber.value);
});

generatePasswordButton.addEventListener("click", function () {
    generateSecurePassword();
});

// ======================================================
// GENERATED PASSWORD ACTIONS
// ======================================================

copyGeneratedPasswordButton.addEventListener("click", async function () {

    const password = generatedPasswordInput.value;

    if (password.length === 0) {
        return;
    }

    try {
        await navigator.clipboard.writeText(password);
        generatedCopyStatus.textContent = "✓ Generated password copied.";

        setTimeout(function () {
            generatedCopyStatus.textContent = "";
        }, 2000);
    }
    catch (error) {
        generatedCopyStatus.textContent = "Unable to copy generated password.";
    }
});

useGeneratedPasswordButton.addEventListener("click", function () {

    const password = generatedPasswordInput.value;

    if (password.length === 0) {
        return;
    }

    passwordInput.value = password;
    passwordInput.type = "text";
    togglePasswordButton.textContent = "🙈";
    togglePasswordButton.title = "Hide password";

    analyzePassword();
    generatorStatus.textContent = "✓ Generated password copied to the analyzer.";
});


// ======================================================
// START APPLICATION
// ======================================================

syncGeneratorLength(20);
copyGeneratedPasswordButton.disabled = true;
useGeneratedPasswordButton.disabled = true;
resetAnalysis();
loadRockyouWordlist();
