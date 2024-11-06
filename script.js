import * as THREE from 'https://cdn.skypack.dev/three@0.132.2';
import { GLTFLoader } from 'https://cdn.skypack.dev/three@0.132.2/examples/jsm/loaders/GLTFLoader.js';

let csvData = []; // Global variable to hold CSV data
let scene, camera, renderer; // Declare global variables for the Three.js components
let currentCuboids = []; // Track the currently displayed cuboids
let scrollableCuboids = [];
let scrollableFrenchCuboids= []; // To keep track of scrollable cuboids
let raycaster, mouse;
let currentWordIndex = 0; // This will keep track of how many words have been shown out of 20
const totalWords = 20; // The total number of words for tracking
let correctWordsCount = 0;  // Track the number of correct words spoken
let totalTestWords = 20;        // Total number of words to display (assume there are 20 for the test)


// Define the animate function
function animate() {
    requestAnimationFrame(animate);

    // Rotate current cuboids if they exist
    currentCuboids.forEach(cuboid => {
        cuboid.rotation.y += 0.01; // Rotate cuboids
    });

    // Rotate scrollable cuboids
    scrollableCuboids.forEach(cuboid => {
        cuboid.rotation.y += 0.01; // Rotate each scrollable cuboid
    });

    renderer.render(scene, camera);
}

// Event listeners
document.getElementById('start-button').addEventListener('click', startLearning);


// Start learning function
async function startLearning() {
    console.log("Get Started button clicked");
    const startScreen = document.getElementById('startScreen');
    const cuboidScreen = document.getElementById('cuboid-screen');
    const container = document.getElementById('cuboid-container');

    // Hide the hero section, navigation bar, and footer
    document.getElementById('hero').style.display = 'none';
    document.getElementById('navbar').style.display = 'none';
    document.getElementById('footer').style.display = 'none';

    // Hide the start screen and show the cuboid screen
    startScreen.classList.remove('active');
    startScreen.style.display = 'none';
    cuboidScreen.classList.add('active');
    cuboidScreen.style.display = 'flex';
    container.style.display = 'block';

    // Fetch the CSV file when starting
    await fetchCSVData();

    // Initialize the cuboids
    initInitialCuboids(); 
}

// Function to fetch CSV data from a file
async function fetchCSVData() {
    const targetUrl = './eng-french.csv'; // Relative path to the local CSV file

    try {
        const response = await fetch(targetUrl); 

        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const text = await response.text(); 
        const rows = text.split('\n').slice(1); // Skip the header row

        // Parse the CSV data
        csvData = rows.map(row => {
            const [english, french] = row.split(',');
            return { english, french }; 
        });
        alert('CSV data loaded successfully!');
    } catch (error) {
        console.error('Error loading CSV data:', error);
        alert('Error loading CSV data. Please ensure the file is in the correct location.');
    }
}

// Initialize the 3D cuboids (initial three)
function initInitialCuboids() {
    const container = document.getElementById("cuboid-container");

    // Setup Three.js scene
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0xfddde6); 

    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.z = 5; 

    renderer = new THREE.WebGLRenderer();
    renderer.setSize(window.innerWidth, window.innerHeight);
    container.appendChild(renderer.domElement);

    const light = new THREE.DirectionalLight(0xffffff, 1);
    light.position.set(1, 1, 1).normalize();
    scene.add(light);

    const labels = ['Learn', 'Practice', 'Test'];
    const cuboidGeometry = new THREE.BoxGeometry(1, 1, 1); 
    
    labels.forEach((label, index) => {
        const textMaterial = new THREE.MeshBasicMaterial({ map: createTextTexture(label, 'black', 'bold', '#ADD8E6') });
    
        // Light blue material for the sides without text
        const lightBlueMaterial = new THREE.MeshStandardMaterial({ color: 0xADD8E6 });
        
        // Assign textMaterial to all sides (front, back, left, right), but set them all to have a light blue color behind the text
        const materials = [
            textMaterial,      // Front side with text
            textMaterial,      // Back side with text
            lightBlueMaterial, // Top side (light blue)
            lightBlueMaterial, // Bottom side (light blue)
            textMaterial,      // Left side with text
            textMaterial       // Right side with text
        ];
    
        const cuboid = new THREE.Mesh(cuboidGeometry, materials);
        currentCuboids.push(cuboid); 
    
        const spacing = 3;
        cuboid.position.x = (index - 1) * spacing; 
        cuboid.position.y = 0;
        cuboid.position.z = 0;
    
        scene.add(cuboid);
    });
    

    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    window.addEventListener('click', onMouseClick, false);

    let testCuboids = []; // Track test cuboids globally

    function onMouseClick(event) {
        mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
        mouse.y = - (event.clientY / window.innerHeight) * 2 + 1;
    
        raycaster.setFromCamera(mouse, camera);
        const intersects = raycaster.intersectObjects(currentCuboids.concat(scrollableCuboids,scrollableFrenchCuboids)); // Intersect all visible cuboids
    
        if (intersects.length > 0) {
            const clickedCuboid = intersects[0].object;
            
            if (clickedCuboid === currentCuboids[0]) { // Check if "Learn" cuboid is clicked
                console.log("Learn clicked!");
                currentCuboids.forEach(cuboid => scene.remove(cuboid)); // Remove all cuboids
                currentCuboids = []; 
                createScrollableCuboids(); // Move to next phase (scrollable cuboids)
            } else if (scrollableCuboids.includes(clickedCuboid)) {
                // Handle chapter cuboid click
                console.log("Chapter cuboid clicked!");
                const index = clickedCuboid.userData.index;
                document.getElementById('skip-button').style.display = 'block';
                displayWord(index); // Display the corresponding word
            }
            
            // Add the conditions for "Practice" cuboid click and specific cuboids
            if (clickedCuboid === currentCuboids[1]) { // Check if "Test" cuboid is clicked
                console.log("Practice clicked!");
                currentCuboids.forEach(cuboid => scene.remove(cuboid)); // Remove all cuboids
                currentCuboids = []; 
                createPracticeCuboidsSet(); // Move to next phase
            }

            if (scrollableFrenchCuboids.includes(clickedCuboid)) {
                const label = clickedCuboid.userData.label;
                console.log(`${label} cuboid clicked!`);

                // Show the progress bar
                const progressBarContainer = document.getElementById('progress-bar-container');
                if (progressBarContainer) {
                console.log("Displaying progress bar");
                progressBarContainer.style.display = 'block';
                }

                const skipButton = document.getElementById('skip-button');
                if (skipButton) {
                console.log("Displaying skip button");
                skipButton.style.display = 'block';
                }


                for (let i = 1; i <= 20; i++) {
                    if (label === `Case ${i}`) { // Use template literals to include the value of i
                        displayRandomWord(); // Function to show a random French word
                    }
                }
                
            }

            if (clickedCuboid === currentCuboids[2]) { // Check if "Test" cuboid is clicked
                console.log("Test clicked!");
                currentCuboids.forEach(cuboid => scene.remove(cuboid)); // Remove all cuboids
                currentCuboids = []; 
                loadGLTFModel(); // Load the GLTF model
            }
        }
    }
    

    animate();
}


// Function to animate the test cuboids
function animatePracticeCuboids(cuboids) {
    function animate() {
        requestAnimationFrame(animate);
        cuboids.forEach(cuboid => {
            cuboid.rotation.y += 0.01; // Rotate each test cuboid
        });
        renderer.render(scene, camera);
    }
    animate(); // Start the animation loop for test cuboids
}

// Function to create scrollable cuboids with text on the front, back, left, and right sides
function createScrollableCuboids() {
    scrollableCuboids.forEach(cuboid => {
        scene.remove(cuboid);
    });
    scrollableCuboids = []; 

    const scrollableCuboidGeometry = new THREE.BoxGeometry(0.7, 0.7, 0.7);
    const horizontalSpacing = 1.5; // Horizontal spacing for 10 cuboids per row
    const verticalSpacing = 1.7; // Vertical spacing between rows
    const initialYPosition = 2.7; // Adjust based on how you want the cuboids to fit vertically
    const totalCuboids = 32;
const cuboidsPerRow = 8;

for (let i = 0; i < totalCuboids; i++) {
    const chapterNumber = i + 1;
    const labelText = `Chapter ${chapterNumber}`;

    // Create textures for the four sides with text (front, back, left, right)
    const textFront = new THREE.MeshBasicMaterial({ map: createTextTexture(labelText, 'black', 'bold', '#f9f0ba') });
    const textBack = new THREE.MeshBasicMaterial({ map: createTextTexture(labelText, 'black', 'bold', '#f9f0ba') });
    const textLeft = new THREE.MeshBasicMaterial({ map: createTextTexture(labelText, 'black', 'bold', '#f9f0ba') });
    const textRight = new THREE.MeshBasicMaterial({ map: createTextTexture(labelText, 'black', 'bold', '#f9f0ba') });

    // Materials for the cuboid (front, back, left, right with text, top and bottom are blank/light blue)
    const materials = [
        textFront, // Front side with text
        textBack,  // Back side with text
        new THREE.MeshStandardMaterial({ color: 0xf9f0ba }), // Top side (no text)
        new THREE.MeshStandardMaterial({ color: 0xf9f0ba }), // Bottom side (no text)
        textLeft,  // Left side with text
        textRight  // Right side with text
    ];

    const cuboid = new THREE.Mesh(scrollableCuboidGeometry, materials);
    scrollableCuboids.push(cuboid);

    // Adjust cuboid positioning for 8 per row
    cuboid.position.x = ((i % cuboidsPerRow) - (cuboidsPerRow / 2 - 0.5)) * horizontalSpacing;
    cuboid.position.y = initialYPosition - Math.floor(i / cuboidsPerRow) * verticalSpacing;
    cuboid.position.z = 0;

    cuboid.userData = { index: i };

    scene.add(cuboid);
}

animate();
}


// Function to display the word after clicking on a chapter
function displayWord(index) {
    const currentWord = csvData[index];
    if (currentWord) {
        const frenchWord = currentWord.french;
        const englishWord = currentWord.english;

        const cuboidScreen = document.getElementById('cuboid-screen');
        cuboidScreen.style.backgroundColor = 'white';
        cuboidScreen.innerHTML = `
            <h1 style="font-size: 48px; color: black; font-weight: bold; text-align: center; margin-top: 20vh;">${frenchWord}</h1>
            <h2 style="font-size: 36px; color: black; text-align: center;">${englishWord}</h2>
            <h3 style="font-size: 24px; color: grey; text-align: center; margin-top: 10vh;">Speaking now...</h3>`;

        // Speak the French and English words
        speakWords(frenchWord, englishWord)
            .then(() => startSpeechRecognition(frenchWord, index)); // Start recognition after speaking

            
            document.getElementById('skip-button').addEventListener('click', function() {
                console.log("Skip button clicked!");
                displayWord(index+1); // Display the next word
            });
    }
}

function speakWords(frenchWord, englishWord) {
    return new Promise((resolve, reject) => {
        const utteranceFrench = new SpeechSynthesisUtterance(frenchWord);
        const utteranceEnglish = new SpeechSynthesisUtterance(englishWord);

        // Function to set voices and speak
        function setVoicesAndSpeak() {
            const voices = window.speechSynthesis.getVoices();

            // Select proper voices
            const frenchVoice = voices.find(voice => voice.lang === 'fr-FR');
            const englishVoice = voices.find(voice => voice.lang === 'en-US');

            if (!frenchVoice || !englishVoice) {
                reject("Required voices not found.");
                return;
            }

            utteranceFrench.voice = frenchVoice;
            utteranceEnglish.voice = englishVoice;

            console.log("Is speaking before start:", window.speechSynthesis.speaking);
            // Clear any pending speech
            window.speechSynthesis.cancel();

            // Start speaking the French word
            window.speechSynthesis.speak(utteranceFrench);
            utteranceFrench.onerror = (e) => {
                reject(e);
            };
            utteranceFrench.onend = () => {
                window.speechSynthesis.speak(utteranceEnglish);
            };
            utteranceEnglish.onerror = (e) => {
                reject(e);
            };
            utteranceEnglish.onend = () => {
                resolve();
            };
        }

        // Check if voices are already loaded
        if (window.speechSynthesis.getVoices().length > 0) {
            setVoicesAndSpeak();
        } else {
            // Wait for voices to be loaded
            window.speechSynthesis.onvoiceschanged = () => {
                setVoicesAndSpeak();
            };
        }
    });
}

// Example usage triggered by a button click to satisfy browser requirements
document.getElementById("speakButton").addEventListener("click", () => {
    speakWords("Bonjour", "Hello").then(() => {
        console.log("Speech finished");
    }).catch(error => {
        console.error("Error during speech:", error);
    });
});

function startSpeechRecognition(correctWord, index) {
    const recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
    recognition.lang = 'fr-FR';

    recognition.start();

    recognition.onstart = function() {
        console.log("Speech recognition started. Please speak...");
    };

    recognition.onresult = function(event) {
        const spokenWord = event.results[0][0].transcript.trim().toLowerCase();
        console.log('Spoken word:', spokenWord);

        // Compare spoken word with the correct French word
        if (spokenWord === correctWord) {
            showResultMessage("Correct!", "lightgreen");
            correctWordsCount++; // Increment correct words count
            
            // Check if the index is the last word
            if (index < csvData.length - 1) {
                displayWord(index + 1); // Display the next word
            } else {
                // All words are completed
                showResultMessage("You've completed all chapters!", "lightblue");
                showSubmitButton(); // Show the submit button when all chapters are done
            }
        } else {
            showResultMessage("Wrong! Please try again.", "red");
            startSpeechRecognition(correctWord, index); // Restart recognition for the same word
        }
    };

    recognition.onerror = function(event) {
        console.error('Speech recognition error:', event.error);
        alert('An error occurred during speech recognition: ' + event.error);
    };
}


// Function to display result message after speech recognition
function showResultMessage(message, color) {
    const cuboidScreen = document.getElementById('cuboid-screen');
    cuboidScreen.style.backgroundColor = color; // Set the background color based on result
    cuboidScreen.innerHTML += `
        <h3 style="font-size: 36px; color: ${color === 'lightgreen' ? 'black' : 'white'}; 
        text-align: center; margin-top: 20px;">${message}</h3>`;
}

let frenchWords = []; // Array to store the loaded French words

// Function to load French words from CSV file
function loadFrenchWords() {
    fetch('eng-french.csv') // Update this with the actual path to your CSV file
        .then(response => response.text())
        .then(data => {
            // Use PapaParse to parse CSV data
            const parsedData = Papa.parse(data, { header: true });
            frenchWords = parsedData.data.map(row => row.frenchWord).filter(Boolean); // Assuming the French words are under the header 'frenchWord'
        })
        .catch(error => console.error('Error loading CSV:', error));
}

// Call the function to load French words when the application starts
loadFrenchWords();

// Create practice cuboids and set click events
function createPracticeCuboidsSet() {
    scrollableFrenchCuboids.forEach(cuboid => {
        scene.remove(cuboid);
    });
    scrollableFrenchCuboids = []; 
    const cuboidGeometry = new THREE.BoxGeometry(0.6, 0.6, 0.6);
    
    const horizontalSpacing = 1.7; // Horizontal spacing between cuboids
    const verticalSpacing = 1.7; // Vertical spacing between cuboids
    const initialYPosition = 2.5; // Initial Y position for the cuboids

    const labels = [
        'Case 1', 'Case 2', 'Case 3', 'Case 4', 'Case 5',
        'Case 10', 'Case 9', 'Case 8', 'Case 7', 'Case 6',
        'Case 11', 'Case 12', 'Case 13', 'Case 14','Case 15', 
        'Case 20', 'Case 19', 'Case 18', 'Case 17', 'Case 16'
    ];
    const practiceCuboids = []; // Array to keep track of practice cuboids

    labels.forEach((label, index) => {
        // Create materials for each side of the cuboid
        const textFront = new THREE.MeshBasicMaterial({ map: createTextTexture(label, 'black', 'bold','#e8d3f1 ') });
        const textBack = new THREE.MeshBasicMaterial({ map: createTextTexture(label, 'black', 'bold','#e8d3f1 ') });
        const textLeft = new THREE.MeshBasicMaterial({ map: createTextTexture(label, 'black', 'bold','#e8d3f1 ') });
        const textRight = new THREE.MeshBasicMaterial({ map: createTextTexture(label, 'black', 'bold','#e8d3f1 ') });

        // Materials for the cuboid (front, back, left, right with text, top and bottom are blank/light blue)
        const materials = [
            textFront, // Front side
            textBack,  // Back side
            new THREE.MeshStandardMaterial({ color: 0xe8d3f1 }), // Top side (no text)
            new THREE.MeshStandardMaterial({ color: 0xe8d3f1 }), // Bottom side (no text)
            textLeft,  // Left side
            textRight  // Right side
        ];

        const cuboid = new THREE.Mesh(cuboidGeometry, materials);
        practiceCuboids.push(cuboid); // Add to the practice cuboids array

        // Position cuboids in a grid-like pattern
        cuboid.position.x = ((index % 5) - 2) * horizontalSpacing; // 5 cuboids per row
        cuboid.position.y = initialYPosition - Math.floor(index / 5) * verticalSpacing; // New row after every 5 cuboids
        cuboid.position.z = 0;

        cuboid.userData = { label }; // Store the label for identification
        scrollableFrenchCuboids.push(cuboid);
        scene.add(cuboid); // Add cuboid to the scene
    });

    animatePracticeCuboids(practiceCuboids); // Animate the practice cuboids
}

// Function to display a random French word when "Greetings" cuboid is clicked
function displayRandomWord() {
    if (currentWordIndex < totalWords) {
        const randomIndex = Math.floor(Math.random() * 100);
        const frenchWord = csvData[randomIndex];
        
        if (frenchWord) {
            // Display the French word on screen
            const cuboidScreen = document.getElementById('cuboid-screen');
            cuboidScreen.innerHTML = `<h1 style="font-size: 48px; color: black; font-weight: bold; text-align: center;">${frenchWord.french}</h1>`;
            
            // Speak the French word
            startSpeechRecognition(frenchWord.french, randomIndex);
            
            // Update the progress
            updateProgressBar();

            document.getElementById('skip-button').addEventListener('click', function() {
                console.log("Skip button clicked!");
                displayRandomWord(); // Display the next random word
            });
        }
    }
}

// Function to update the progress bar
function updateProgressBar() {
    if (currentWordIndex < totalWords) {
        currentWordIndex++; // Increment word index each time

        // Calculate the progress percentage
        const progressPercentage = (currentWordIndex / totalWords) * 100;

        // Update the width of the progress bar
        const progressBar = document.getElementById('progress-bar');
        if (progressBar) {
            progressBar.style.width = progressPercentage + '%';
        }

        // Check if all words have been displayed
        if (currentWordIndex === totalWords) {
            const cuboidScreen = document.getElementById('cuboid-screen');
            if (cuboidScreen) {
                cuboidScreen.innerHTML = `<h1 style="font-size: 48px; color: black; text-align: center;">You have completed all the words!<br><br></h1>`;
                displayFinalScore();
            }
        }
    }
}

function handleCuboidClick() {
    const progressBarContainer = document.getElementById('progress-bar-container');
    
    // Show the progress bar container
    if (progressBarContainer) {
        console.log("Displaying progress bar"); // Debugging line
        progressBarContainer.style.display = 'block'; // Show the progress bar
    }

    // Start updating the progress and display a random word
    displayRandomWord();
}

// Add event listeners to the currently displayed cuboids
currentCuboids.forEach(cuboid => {
    cuboid.userData.label = 'Your label'; // You can set this based on your need
    cuboid.addEventListener('click', handleCuboidClick);
});

function showSubmitButton() {
    console.log('Attempting to show the submit button');
    const submitButton = document.getElementById('submitButton');
    if (submitButton) {
        submitButton.style.display = 'block'; // Show the button
        displayFinalScore();
    } else {
        console.error('Submit button element not found.');
    }
}


function displayFinalScore() {
    const cuboidScreen = document.getElementById('cuboid-screen');
    cuboidScreen.style.backgroundColor = 'white';
    cuboidScreen.innerHTML = `
        <h1 style="font-size: 48px; color: black; font-weight: bold; text-align: center;">Test Completed, Congrats!</h1>
        <h2 style="font-size: 36px; color: black; text-align: center;">You got ${correctWordsCount} out of ${totalTestWords} correct</h2>`;
}

function createTextTexture(text, textColor, fontWeight, backgroundColor = '#FFFFFF') {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    canvas.width = 256;
    canvas.height = 256;

    // Set background color
    context.fillStyle = backgroundColor;
    context.fillRect(0, 0, canvas.width, canvas.height);

    // Set text properties
    context.fillStyle = textColor;
    context.font = `${fontWeight} 48px Arial`;
    context.textAlign = 'center';
    context.textBaseline = 'middle';

    // Draw text in the center of the canvas
    context.fillText(text, canvas.width / 2, canvas.height / 2);

    const texture = new THREE.CanvasTexture(canvas);
    return texture;
}


let person1, person2;
function loadGLTFModel() {
    const loader = new GLTFLoader();

    // Load the main scene model
    loader.load('./models/scene.gltf', function (gltf) {
        const model = gltf.scene;

        // Set model position, scale, and rotation as needed
        model.position.set(0.3, -1, 1.5);
        model.scale.set(1, 1, 1);
        model.rotation.set(0, 0, 0);

        scene.add(model); // Add model to the scene
        scene.background = new THREE.Color(0xFFFFFF); // Set background color

        const ambientLight = new THREE.AmbientLight(0xffffff, 0.1); // soft white light
scene.add(ambientLight);

const pointLight = new THREE.PointLight(0xffffff, 1); // stronger light
pointLight.position.set(5, 10, 5);
scene.add(pointLight);


        // Load two additional people models
        loadPeopleModels();  // Call the function to load people models

        // Animate the model (optional)
        function animateModel() {
            requestAnimationFrame(animateModel);
            renderer.render(scene, camera);
        }

        animateModel(); // Start animation
    }, undefined, function (error) {
        console.error('An error occurred loading the GLTF model:', error);
        alert('Error loading the 3D model.');
    });
}

// Function to load two people models
function loadPeopleModels() {
    const loader = new GLTFLoader();

    // Load the first person model
    loader.load('./models/People/1/person1.gltf', function (gltf) {
        person1 = gltf.scene;  // Assign to the globally declared person1 variable
        person1.scale.set(0.5, 0.5, 0.5);
        person1.position.set(-0.2, -0.8, 2); // Facing towards person2's position
        person1.rotation.y = Math.PI / 4;  // Make person1 face person2
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.5); // soft white light
scene.add(ambientLight);

const pointLight = new THREE.PointLight(0xffffff, 1); // stronger light
pointLight.position.set(5, 10, 5);
scene.add(pointLight);

        scene.add(person1);

        console.log("Person 1 added to the scene");

        // Load the second person model after person1 is added
        loader.load('./models/People/2/person2.gltf', function (gltf) {
            person2 = gltf.scene;  // Assign to the globally declared person2 variable
            person2.scale.set(0.5, 0.5, 0.5);
            person2.position.set(0.5, -0.3, 0);// Facing towards person1's position
            person2.rotation.y = 0;  // Make person2 face person1
            const ambientLight = new THREE.AmbientLight(0xffffff, 0.5); // soft white light
            scene.add(ambientLight);

           const pointLight = new THREE.PointLight(0xffffff, 1); // stronger light
           pointLight.position.set(5, 10, 5);
           scene.add(pointLight);

            scene.add(person2);

            console.log("Person 2 added to the scene");

            // Start conversation simulation between person1 and person2
            simulateConversation(person1, person2);
        });
    });
}

// Function to create the speech bubble
function createSpeechBubble(text) {
    const speechBubble = document.createElement('div');
    speechBubble.className = 'speech-bubble';
    speechBubble.innerHTML = text;
    document.body.appendChild(speechBubble);
    
    return speechBubble;
}

function updateSpeechBubblePosition(person, speechBubble, isPerson1) {
    const vector = new THREE.Vector3();
    const canvas = renderer.domElement;

    person.getWorldPosition(vector);
    vector.project(camera);

    const x = (vector.x * 0.5 + 0.5) * canvas.clientWidth;
    const y = (1 - (vector.y * 0.5 + 0.5)) * canvas.clientHeight;

    // Adjust horizontal and vertical offsets
    const bubbleOffsetX = isPerson1 ? -90 : -80; // Adjust as needed
    const bubbleOffsetY = isPerson1 ? -150 : -120; // Adjust as needed for height

    // Set position of the speech bubble
    speechBubble.style.left = `${x + bubbleOffsetX}px`; 
    speechBubble.style.top = `${y + bubbleOffsetY}px`; 
}

let talkingIndex = 0; // Track the dialogue index
let attemptCount = 0; // Track the user's attempts
const maxAttempts = 3;  // Maximum number of attempts

// Function to speak text
function speakText(text, onEnd) {
    const speech = new SpeechSynthesisUtterance(text);
    speech.lang = 'fr-FR'; // French language

    speech.onend = () => {
        if (onEnd) onEnd(); // Call the callback if provided
    };

    window.speechSynthesis.speak(speech);
}

// Function to recognize user speech input
function recognizeSpeech(expectedText, onResult) {
    const recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
    recognition.lang = 'fr-FR'; // French recognition language

    recognition.onresult = (event) => {
        const spokenText = event.results[0][0].transcript; // Get the recognized speech
        console.log("User said: ", spokenText);
        if (onResult) onResult(spokenText);
    };

    recognition.onerror = (event) => {
        console.error("Speech recognition error:", event.error);
        if (onResult) onResult(null); // If there's an error, return null
    };

    recognition.start();
}

function simulateConversation() {
    const dialogues = [
        { speaker: "person1", text: "Bonjour!<br>(Hello!)" },
        { speaker: "person2", text: "Comment puis-je vous aider aujourd'hui ?<br>(How can I help you today?)" },
        { speaker: "person1", text: "Je cherche quelque chose à boire. Avez-vous des recommandations ?<br>(I’m looking for something to drink. Do you have any recommendations?)" },
        { speaker: "person2", text: "Absolument! Notre moka glacé est un favori, surtout par temps chaud.<br>(Absolutely! Our iced mocha is a favorite, especially on warm days.)" },
        { speaker: "person1", text: "Ça a l'air sympa ! Que recommandez-vous d'autre ?<br>(That sounds nice! What else do you recommend?)" },
        { speaker: "person2", text: "Bien sûr! Notre café au lait est un incontournable ici, surtout avec un croissant. <br>(Of course! Our café au lait is a must-try here, especially with a croissant.)" },
        { speaker: "person1", text: "Cela a l'air délicieux! Que me recommandez-vous d'autre?<br> (That sounds delicious! What else do you recommend?)" },
        { speaker: "person2", text: "Si vous aimez les boissons froides, je vous conseille un verre de kir, un apéritif à base de crème de cassis et de vin blanc.<br> (If you like cold drinks, I recommend a glass of kir, an aperitif made with blackcurrant liqueur and white wine.)" },
        { speaker: "person1", text: "Hmm, j'adore le kir! Je vais essayer ça.<br> (Hmm, I love kir! I’ll try that.)" },
        { speaker: "person2", text: "Excellent choix! Aimeriez-vous un dessert avec votre boisson?<br> (Great choice! Would you like a dessert with your drink?)" },
        { speaker: "person1", text: "Oui! Que recommandez-vous? <br>(Yes! What do you recommend?)" },
        { speaker: "person2", text: "Notre tarte Tatin est divine, et notre éclair au chocolat est un classique.<br> (Our tarte Tatin is divine, and our chocolate éclair is a classic.)" },
        { speaker: "person1", text: "Cela a l'air merveilleux! Je vais prendre une tarte Tatin.<br> (That sounds wonderful! I’ll have a tarte Tatin.)" },
        { speaker: "person2", text: "Très bien! Donc, un kir et une tarte Tatin. Autre chose? <br>(Very well! So that's one kir and one tarte Tatin. Anything else?)" },
        { speaker: "person1", text: "Non, ce sera tout. Combien je vous dois?<br>(No, that will be all. How much do I owe you?)" },
        { speaker: "person2", text: "Cela fera 9,50 €, s'il vous plaît.<br> (That'll be €9.50, please.)" },
        { speaker: "person1", text: "Voici! Merci pour vos recommandations!<br> (Here you go! Thank you for your recommendations!)" },
        { speaker: "person2", text: "Merci! Votre commande sera prête dans un instant.<br>(Thank you! Your order will be ready in just a moment.)" },
    ];

    const speechBubble1 = createSpeechBubble("");
    const speechBubble2 = createSpeechBubble("");

    speechBubble1.style.display = 'none';
    speechBubble2.style.display = 'none';

    function checkPronunciation(userSpokenText, correctText) {
        // Simple pronunciation check logic
        return userSpokenText.trim().toLowerCase() === correctText.trim().toLowerCase();
    }

    function handleUserPronunciation(dialogueText) {
        const textToPronounce = dialogueText.split('<br>')[0]; // Get only the French text to pronounce
    
        // Recognize user speech
        recognizeSpeech(textToPronounce, (userSpokenText) => {
            if (userSpokenText && checkPronunciation(userSpokenText, textToPronounce)) {
                console.log("Correct pronunciation!");
                attemptCount = 0; // Reset attempts
                talkingIndex++; // Move to next dialogue
                talk(); // Continue conversation
            } else {
                attemptCount++;
                console.log(`Incorrect pronunciation. Attempt ${attemptCount} of ${maxAttempts}`);
    
                // Speak the correct text after an incorrect attempt
                speakText(textToPronounce, () => {
                    // After speaking, check if we need to retry or move on
                    if (attemptCount >= maxAttempts) {
                        console.log("Max attempts reached. Moving on...");
                        attemptCount = 0; // Reset attempts
                        talkingIndex++; // Move to next dialogue
                        talk(); // Continue conversation
                    } else {
                        console.log("Retrying pronunciation...");
                        handleUserPronunciation(dialogueText); // Retry pronunciation after speaking the word
                    }
                });
            }
        });
    }        

    function talk() {
        if (talkingIndex < dialogues.length) {
            const dialogue = dialogues[talkingIndex];

            if (dialogue.speaker === 'person1') {
                person1.rotation.y = Math.PI / 2 + 0.1;
                person2.rotation.y = -Math.PI / 2;
                speechBubble1.style.display = 'block';
                speechBubble2.style.display = 'none';
                speechBubble1.innerHTML = dialogue.text;

                console.log(`Person 1 says: "${dialogue.text}"`);
                handleUserPronunciation(dialogue.text); // Check user pronunciation

            } else if (dialogue.speaker === 'person2') {
                person2.rotation.y = -Math.PI / 2 - 0.1;
                person1.rotation.y = Math.PI / 2;
                speechBubble2.style.display = 'block';
                speechBubble1.style.display = 'none';
                speechBubble2.innerHTML = dialogue.text;

                const textToSpeak = dialogue.text.split('<br>')[0];
                console.log(`Person 2 says: "${textToSpeak}"`);
                speakText(textToSpeak, () => {
                    talkingIndex++; // Move to next dialogue after person 2 speaks
                    talk(); // Continue the conversation
                });
            }

            if (speechBubble1.style.display === 'block') {
                updateSpeechBubblePosition(person1, speechBubble1);
            }
            if (speechBubble2.style.display === 'block') {
                updateSpeechBubblePosition(person2, speechBubble2);
            }
        }
    }

    talk(); // Start the conversation
}

function onWindowResize() {
    if (renderer) {
        renderer.setSize(window.innerWidth, window.innerHeight);
    }
    if (camera) {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
    }
}

// Add the event listener
window.addEventListener('resize', onWindowResize, false);
