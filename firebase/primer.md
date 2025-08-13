# Firebase Primer

## Overview
Firebase is Google's comprehensive Backend-as-a-Service (BaaS) platform that provides a suite of tools for building web and mobile applications. It offers real-time databases, authentication, hosting, cloud functions, analytics, and more, allowing developers to focus on frontend development while Firebase handles the backend infrastructure.

## Key Features
- **Authentication**: User management with multiple providers
- **Firestore**: NoSQL document database with real-time sync
- **Realtime Database**: JSON-based real-time database
- **Cloud Functions**: Serverless backend logic
- **Hosting**: Fast, secure web hosting
- **Cloud Storage**: File storage with CDN
- **Analytics**: App usage and user behavior tracking
- **Cloud Messaging**: Push notifications

## Firebase Architecture
Firebase services are organized into several categories:
- **Build**: Core app functionality (Firestore, Auth, Functions, Hosting, Storage)
- **Release & Monitor**: App deployment and performance monitoring
- **Analytics**: User behavior and app performance insights
- **Engage**: User engagement tools (messaging, remote config)

## Authentication

### Setup and Basic Usage
```javascript
// Initialize Firebase
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword } from 'firebase/auth';

const firebaseConfig = {
  apiKey: "your-api-key",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project-id",
  storageBucket: "your-project.appspot.com",
  messagingSenderId: "123456789",
  appId: "your-app-id"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

// Sign up new user
const signUp = async (email, password) => {
  try {
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    return userCredential.user;
  } catch (error) {
    console.error('Error signing up:', error.message);
    throw error;
  }
};

// Sign in existing user
const signIn = async (email, password) => {
  try {
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    return userCredential.user;
  } catch (error) {
    console.error('Error signing in:', error.message);
    throw error;
  }
};
```

### Social Authentication
```javascript
import { signInWithPopup, GoogleAuthProvider, FacebookAuthProvider } from 'firebase/auth';

// Google Sign-In
const signInWithGoogle = async () => {
  const provider = new GoogleAuthProvider();
  try {
    const result = await signInWithPopup(auth, provider);
    return result.user;
  } catch (error) {
    console.error('Error with Google sign-in:', error);
    throw error;
  }
};

// Facebook Sign-In
const signInWithFacebook = async () => {
  const provider = new FacebookAuthProvider();
  try {
    const result = await signInWithPopup(auth, provider);
    return result.user;
  } catch (error) {
    console.error('Error with Facebook sign-in:', error);
    throw error;
  }
};
```

## Firestore Database

### Basic CRUD Operations
```javascript
import { 
  getFirestore, 
  collection, 
  doc, 
  addDoc, 
  getDoc, 
  getDocs, 
  updateDoc, 
  deleteDoc,
  query,
  where,
  orderBy,
  limit
} from 'firebase/firestore';

const db = getFirestore(app);

// Create document
const createUser = async (userData) => {
  try {
    const docRef = await addDoc(collection(db, 'users'), {
      ...userData,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    console.log('User created with ID: ', docRef.id);
    return docRef.id;
  } catch (error) {
    console.error('Error creating user:', error);
    throw error;
  }
};

// Read single document
const getUser = async (userId) => {
  try {
    const docRef = doc(db, 'users', userId);
    const docSnap = await getDoc(docRef);
    
    if (docSnap.exists()) {
      return { id: docSnap.id, ...docSnap.data() };
    } else {
      console.log('No such document!');
      return null;
    }
  } catch (error) {
    console.error('Error getting user:', error);
    throw error;
  }
};

// Read multiple documents with query
const getActiveUsers = async () => {
  try {
    const q = query(
      collection(db, 'users'),
      where('active', '==', true),
      orderBy('createdAt', 'desc'),
      limit(10)
    );
    
    const querySnapshot = await getDocs(q);
    const users = [];
    querySnapshot.forEach((doc) => {
      users.push({ id: doc.id, ...doc.data() });
    });
    
    return users;
  } catch (error) {
    console.error('Error getting users:', error);
    throw error;
  }
};

// Update document
const updateUser = async (userId, updates) => {
  try {
    const docRef = doc(db, 'users', userId);
    await updateDoc(docRef, {
      ...updates,
      updatedAt: new Date()
    });
    console.log('User updated successfully');
  } catch (error) {
    console.error('Error updating user:', error);
    throw error;
  }
};

// Delete document
const deleteUser = async (userId) => {
  try {
    const docRef = doc(db, 'users', userId);
    await deleteDoc(docRef);
    console.log('User deleted successfully');
  } catch (error) {
    console.error('Error deleting user:', error);
    throw error;
  }
};
```

### Real-time Listeners
```javascript
import { onSnapshot } from 'firebase/firestore';

// Listen to single document changes
const listenToUser = (userId, callback) => {
  const docRef = doc(db, 'users', userId);
  
  const unsubscribe = onSnapshot(docRef, (docSnap) => {
    if (docSnap.exists()) {
      callback({ id: docSnap.id, ...docSnap.data() });
    } else {
      callback(null);
    }
  });
  
  return unsubscribe; // Call this to stop listening
};

// Listen to query results
const listenToActiveUsers = (callback) => {
  const q = query(
    collection(db, 'users'),
    where('active', '==', true)
  );
  
  const unsubscribe = onSnapshot(q, (querySnapshot) => {
    const users = [];
    querySnapshot.forEach((doc) => {
      users.push({ id: doc.id, ...doc.data() });
    });
    callback(users);
  });
  
  return unsubscribe;
};
```

## Cloud Functions

### HTTP Functions
```javascript
// functions/index.js
const { onRequest } = require('firebase-functions/v2/https');
const { initializeApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

initializeApp();
const db = getFirestore();

// HTTP callable function
exports.createUserProfile = onRequest(async (req, res) => {
  try {
    const { uid, email, displayName } = req.body;
    
    const userProfile = {
      uid,
      email,
      displayName,
      createdAt: new Date(),
      isActive: true
    };
    
    const docRef = await db.collection('userProfiles').doc(uid).set(userProfile);
    
    res.status(200).json({ 
      success: true, 
      message: 'User profile created successfully' 
    });
  } catch (error) {
    console.error('Error creating user profile:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});
```

### Firestore Triggers
```javascript
const { onDocumentCreated, onDocumentUpdated } = require('firebase-functions/v2/firestore');

// Triggered when a new user is created
exports.onUserCreated = onDocumentCreated('users/{userId}', async (event) => {
  const snapshot = event.data;
  const userData = snapshot.data();
  
  console.log('New user created:', userData);
  
  // Send welcome email
  // Update statistics
  // Perform other background tasks
});

// Triggered when a user is updated
exports.onUserUpdated = onDocumentUpdated('users/{userId}', async (event) => {
  const beforeData = event.data.before.data();
  const afterData = event.data.after.data();
  
  console.log('User updated from:', beforeData, 'to:', afterData);
  
  // Handle user updates
});
```

### Authentication Triggers
```javascript
const { onCall } = require('firebase-functions/v2/https');
const { beforeUserCreated } = require('firebase-functions/v2/identity');

// Pre-process user creation
exports.beforeCreateUser = beforeUserCreated(async (event) => {
  const user = event.data;
  
  // Validate email domain
  if (!user.email.endsWith('@company.com')) {
    throw new Error('Only company emails are allowed');
  }
  
  return {
    customClaims: {
      role: 'user',
      department: 'general'
    }
  };
});
```

## Cloud Storage

### File Upload and Management
```javascript
import { getStorage, ref, uploadBytes, getDownloadURL, deleteObject } from 'firebase/storage';

const storage = getStorage(app);

// Upload file
const uploadFile = async (file, path) => {
  try {
    const storageRef = ref(storage, path);
    const snapshot = await uploadBytes(storageRef, file);
    const downloadURL = await getDownloadURL(snapshot.ref);
    
    console.log('File uploaded successfully');
    return downloadURL;
  } catch (error) {
    console.error('Error uploading file:', error);
    throw error;
  }
};

// Upload with metadata
const uploadFileWithMetadata = async (file, path, metadata) => {
  try {
    const storageRef = ref(storage, path);
    const snapshot = await uploadBytes(storageRef, file, metadata);
    const downloadURL = await getDownloadURL(snapshot.ref);
    
    return {
      downloadURL,
      fullPath: snapshot.ref.fullPath,
      name: snapshot.ref.name
    };
  } catch (error) {
    console.error('Error uploading file:', error);
    throw error;
  }
};

// Delete file
const deleteFile = async (path) => {
  try {
    const storageRef = ref(storage, path);
    await deleteObject(storageRef);
    console.log('File deleted successfully');
  } catch (error) {
    console.error('Error deleting file:', error);
    throw error;
  }
};
```

## Firebase Hosting

### Deployment Commands
```bash
# Install Firebase CLI
npm install -g firebase-tools

# Login to Firebase
firebase login

# Initialize project
firebase init hosting

# Deploy to hosting
firebase deploy

# Deploy only hosting
firebase deploy --only hosting

# Set up custom domain
firebase hosting:channel:deploy preview
```

### Hosting Configuration (firebase.json)
```json
{
  "hosting": {
    "public": "dist",
    "ignore": [
      "firebase.json",
      "**/.*",
      "**/node_modules/**"
    ],
    "rewrites": [
      {
        "source": "**",
        "destination": "/index.html"
      }
    ],
    "headers": [
      {
        "source": "/service-worker.js",
        "headers": [
          {
            "key": "Cache-Control",
            "value": "no-cache"
          }
        ]
      }
    ]
  }
}
```

## Firebase Security Rules

### Firestore Security Rules
```javascript
// firestore.rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only read/write their own profile
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Public posts that anyone can read, but only authenticated users can create
    match /posts/{postId} {
      allow read: if true;
      allow create: if request.auth != null;
      allow update, delete: if request.auth != null && 
        request.auth.uid == resource.data.authorId;
    }
    
    // Admin-only collection
    match /admin/{document} {
      allow read, write: if request.auth != null && 
        request.auth.token.admin == true;
    }
  }
}
```

### Storage Security Rules
```javascript
// storage.rules
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    // Users can upload to their own folder
    match /users/{userId}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Public images
    match /public/{allPaths=**} {
      allow read: if true;
      allow write: if request.auth != null;
    }
  }
}
```

## Analytics and Performance

### Firebase Analytics
```javascript
import { getAnalytics, logEvent } from 'firebase/analytics';

const analytics = getAnalytics(app);

// Log custom events
const trackPurchase = (value, currency, items) => {
  logEvent(analytics, 'purchase', {
    currency: currency,
    value: value,
    items: items
  });
};

// Track page views
const trackPageView = (pageName) => {
  logEvent(analytics, 'page_view', {
    page_title: pageName,
    page_location: window.location.href
  });
};
```

### Performance Monitoring
```javascript
import { getPerformance, trace } from 'firebase/performance';

const perf = getPerformance(app);

// Custom performance trace
const trackApiCall = async (apiFunction) => {
  const t = trace(perf, 'api_call');
  t.start();
  
  try {
    const result = await apiFunction();
    t.putAttribute('status', 'success');
    return result;
  } catch (error) {
    t.putAttribute('status', 'error');
    throw error;
  } finally {
    t.stop();
  }
};
```

## Best Practices

### Security
1. **Use Security Rules**: Always implement proper Firestore and Storage rules
2. **Validate on Server**: Use Cloud Functions for server-side validation
3. **Limit Permissions**: Give users minimal required permissions
4. **Use Admin SDK**: Server-side operations should use Admin SDK

### Performance
1. **Optimize Queries**: Use compound indexes for complex queries
2. **Paginate Results**: Use `startAfter()` for pagination
3. **Cache Data**: Implement proper caching strategies
4. **Batch Operations**: Use batch writes for multiple operations

### Architecture
1. **Denormalize Data**: Structure data for your use cases
2. **Use Subcollections**: For hierarchical data relationships
3. **Implement Offline Support**: Firebase handles offline sync automatically
4. **Monitor Costs**: Keep track of read/write operations

## Common Patterns

### User Profile Management
```javascript
// Create user profile after authentication
const createUserProfileOnSignUp = async (user) => {
  const userProfileRef = doc(db, 'users', user.uid);
  
  await setDoc(userProfileRef, {
    uid: user.uid,
    email: user.email,
    displayName: user.displayName || '',
    photoURL: user.photoURL || '',
    createdAt: new Date(),
    lastLoginAt: new Date()
  });
};
```

### Real-time Chat Implementation
```javascript
// Send message
const sendMessage = async (chatId, message, senderId) => {
  await addDoc(collection(db, 'chats', chatId, 'messages'), {
    text: message,
    senderId: senderId,
    timestamp: new Date(),
    type: 'text'
  });
};

// Listen to messages
const listenToMessages = (chatId, callback) => {
  const q = query(
    collection(db, 'chats', chatId, 'messages'),
    orderBy('timestamp', 'asc')
  );
  
  return onSnapshot(q, (snapshot) => {
    const messages = [];
    snapshot.forEach((doc) => {
      messages.push({ id: doc.id, ...doc.data() });
    });
    callback(messages);
  });
};
```

## Error Handling
```javascript
const handleFirebaseError = (error) => {
  switch (error.code) {
    case 'auth/user-not-found':
      return 'No user found with this email address.';
    case 'auth/wrong-password':
      return 'Incorrect password.';
    case 'auth/email-already-in-use':
      return 'An account with this email already exists.';
    case 'permission-denied':
      return 'You do not have permission to perform this action.';
    case 'not-found':
      return 'The requested document was not found.';
    default:
      return 'An unexpected error occurred. Please try again.';
  }
};
```

## Testing
```javascript
// Firebase emulators for local development
// firebase.json
{
  "emulators": {
    "auth": {
      "port": 9099
    },
    "firestore": {
      "port": 8080
    },
    "functions": {
      "port": 5001
    },
    "hosting": {
      "port": 5000
    },
    "storage": {
      "port": 9199
    }
  }
}
```

## Resources
- [Firebase Documentation](https://firebase.google.com/docs)
- [Firestore Documentation](https://firebase.google.com/docs/firestore)
- [Firebase Authentication Guide](https://firebase.google.com/docs/auth)
- [Cloud Functions Documentation](https://firebase.google.com/docs/functions)
- [Firebase CLI Reference](https://firebase.google.com/docs/cli)
- [Firebase Console](https://console.firebase.google.com)