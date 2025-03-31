/**
 * Telegram Login with AWS Cognito OIDC Integration
 * 
 * This module provides functionality to authenticate users via Telegram's
 * Login Widget and then use the obtained credentials with AWS Cognito.
 */

// Configuration for Cognito and Telegram
const config = {
  // Your Cognito configuration
  cognito: {
    region: 'me-central-1',
    userPoolId: 'me-central-1_tNOgDwh8p', 
    clientId: '6nqpk8h7pbg4j2pvg74i83l48k',
    redirectUri: window.location.origin + '/callback', // Adjust as needed
  },
  telegram: {
    botName: 'gamertag_app_bot',
  },
  oidc: {
    authorizeUrl: 'https://o6q4egqemj.execute-api.me-central-1.amazonaws.com/authorize',
    tokenUrl: 'https://o6q4egqemj.execute-api.me-central-1.amazonaws.com/token',
  }
};

/**
 * Initialize the Telegram Login Widget
 * @param {string} elementId - DOM element ID where the widget should be rendered
 * @param {Function} onAuthCallback - Callback function to handle auth result
 */
function initTelegramLoginWidget(elementId, onAuthCallback) {
  const container = document.getElementById(elementId);
  if (!container) {
    console.error(`Element with ID "${elementId}" not found`);
    return;
  }

  // Create a script element to load the Telegram widget
  const script = document.createElement('script');
  script.src = 'https://telegram.org/js/telegram-widget.js?21';
  script.setAttribute('data-telegram-login', config.telegram.botName);
  script.setAttribute('data-size', 'large');
  script.setAttribute('data-radius', '4');
  script.setAttribute('data-request-access', 'write');
  script.setAttribute('data-userpic', 'false');
  script.setAttribute('data-auth-url', `${window.location.origin}/telegram-auth`);
  script.async = true;

  // Append the script to the container
  container.appendChild(script);

  // Set up a global callback function for the Telegram widget
  window.onTelegramAuth = function(user) {
    handleTelegramAuth(user, onAuthCallback);
  };
}

/**
 * Handle the authentication data received from Telegram
 * @param {Object} telegramUser - User data from Telegram
 * @param {Function} callback - Callback function to handle auth result
 */
function handleTelegramAuth(telegramUser, callback) {
  if (!telegramUser) {
    callback({ success: false, error: 'No user data received from Telegram' });
    return;
  }

  // Verify the authentication data on your backend
  verifyTelegramAuth(telegramUser)
    .then(verificationResult => {
      if (verificationResult.verified) {
        // Initiate Cognito OIDC flow
        initiateOIDCFlow(telegramUser, callback);
      } else {
        callback({ success: false, error: 'Telegram authentication verification failed' });
      }
    })
    .catch(error => {
      console.error('Error verifying Telegram auth:', error);
      callback({ success: false, error: 'Error during Telegram authentication verification' });
    });
}

/**
 * Verify the Telegram authentication data with your backend
 * @param {Object} telegramUser - User data from Telegram
 * @returns {Promise<Object>} - Verification result
 */
async function verifyTelegramAuth(telegramUser) {
  try {
    // You need to implement a backend endpoint to verify the Telegram data
    // This is important for security to prevent forgery
    const response = await fetch('/api/verify-telegram-auth', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(telegramUser),
    });
    
    return await response.json();
  } catch (error) {
    console.error('Error verifying Telegram auth:', error);
    throw error;
  }
}

/**
 * Initiate the OIDC authorization flow with Cognito
 * @param {Object} telegramUser - Verified user data from Telegram
 * @param {Function} callback - Callback function to handle auth result
 */
function initiateOIDCFlow(telegramUser, callback) {
  // Generate a random state parameter for CSRF protection
  const state = generateRandomString(32);
  // Store the state in localStorage for verification when the user returns
  localStorage.setItem('oidc_state', state);
  
  // Generate a nonce for replay protection
  const nonce = generateRandomString(32);
  localStorage.setItem('oidc_nonce', nonce);
  
  // Create the authorization URL with the necessary parameters
  const authUrl = new URL(config.oidc.authorizeUrl);
  authUrl.searchParams.append('client_id', config.cognito.clientId);
  authUrl.searchParams.append('redirect_uri', config.cognito.redirectUri);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', 'openid profile email');
  authUrl.searchParams.append('state', state);
  authUrl.searchParams.append('nonce', nonce);
  
  // Add Telegram user data as custom parameters
  // Note: Your OIDC provider needs to be configured to accept and process these
  authUrl.searchParams.append('telegram_id', telegramUser.id);
  authUrl.searchParams.append('telegram_first_name', telegramUser.first_name);
  if (telegramUser.last_name) {
    authUrl.searchParams.append('telegram_last_name', telegramUser.last_name);
  }
  if (telegramUser.username) {
    authUrl.searchParams.append('telegram_username', telegramUser.username);
  }
  if (telegramUser.photo_url) {
    authUrl.searchParams.append('telegram_photo_url', telegramUser.photo_url);
  }
  
  // Redirect the user to the authorization endpoint
  window.location.href = authUrl.toString();
}

/**
 * Handle the callback from the OIDC provider
 * This should be called on your redirect URI page
 * @returns {Promise<Object>} - Authentication result
 */
async function handleOIDCCallback() {
  // Parse the URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const state = urlParams.get('state');
  const error = urlParams.get('error');
  
  // Check for errors
  if (error) {
    return { success: false, error: error };
  }
  
  // Verify the state parameter to prevent CSRF attacks
  const storedState = localStorage.getItem('oidc_state');
  if (!state || state !== storedState) {
    return { success: false, error: 'Invalid state parameter' };
  }
  
  // Clear the stored state
  localStorage.removeItem('oidc_state');
  
  // Exchange the authorization code for tokens
  try {
    const tokenResponse = await fetch(config.oidc.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: config.cognito.clientId,
        redirect_uri: config.cognito.redirectUri,
        code: code,
      }),
    });
    
    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.json();
      return { success: false, error: errorData.error || 'Failed to exchange code for tokens' };
    }
    
    const tokens = await tokenResponse.json();
    
    // Store the tokens securely
    // Note: In a production app, you should use more secure storage methods
    localStorage.setItem('id_token', tokens.id_token);
    localStorage.setItem('access_token', tokens.access_token);
    if (tokens.refresh_token) {
      localStorage.setItem('refresh_token', tokens.refresh_token);
    }
    
    // Parse the ID token to get user information
    const userInfo = parseJwt(tokens.id_token);
    
    return {
      success: true,
      tokens: tokens,
      user: userInfo,
    };
  } catch (error) {
    console.error('Error exchanging code for tokens:', error);
    return { success: false, error: 'Error exchanging code for tokens' };
  }
}

/**
 * Parse a JWT token to extract the payload
 * @param {string} token - JWT token
 * @returns {Object} - Decoded payload
 */
function parseJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Error parsing JWT:', error);
    return {};
  }
}

/**
 * Generate a random string for state and nonce parameters
 * @param {number} length - Length of the string
 * @returns {string} - Random string
 */
function generateRandomString(length) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomValues = new Uint8Array(length);
  window.crypto.getRandomValues(randomValues);
  randomValues.forEach(value => {
    result += charset[value % charset.length];
  });
  return result;
}

/**
 * Check if the user is authenticated
 * @returns {boolean} - True if the user is authenticated
 */
function isAuthenticated() {
  const idToken = localStorage.getItem('id_token');
  if (!idToken) {
    return false;
  }
  
  // Check if the token is expired
  try {
    const payload = parseJwt(idToken);
    const now = Math.floor(Date.now() / 1000);
    
    return payload.exp > now;
  } catch (error) {
    return false;
  }
}

/**
 * Get the current user information
 * @returns {Object|null} - User information or null if not authenticated
 */
function getCurrentUser() {
  if (!isAuthenticated()) {
    return null;
  }
  
  const idToken = localStorage.getItem('id_token');
  return parseJwt(idToken);
}

/**
 * Log out the current user
 */
function logout() {
  localStorage.removeItem('id_token');
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  
  // Redirect to home page or login page
  window.location.href = '/';
}

/**
 * Initialize the Telegram Login UI
 * This function should be called when the DOM is loaded
 */
function initTelegramLoginUI() {
  // Get references to DOM elements
  const loginContainer = document.getElementById('login-container');
  const userInfoContainer = document.getElementById('user-info');
  const userNameElement = document.getElementById('user-name');
  const userPhotoElement = document.getElementById('user-photo');
  const errorContainer = document.getElementById('error-container');
  const logoutButton = document.getElementById('logout-button');
  
  // Check if we're on the callback page
  const isCallbackPage = window.location.pathname === '/callback';
  
  if (isCallbackPage) {
    // Handle the callback from the OIDC provider
    handleCallback();
  } else {
    // Check if the user is already authenticated
    if (isAuthenticated()) {
      // Show user info
      showUserInfo(getCurrentUser());
    } else {
      // Initialize the Telegram login widget
      initTelegramLoginWidget('telegram-login-container', handleAuthResult);
      
      // Show the login container
      if (loginContainer) {
        loginContainer.style.display = 'flex';
      }
    }
  }
  
  // Set up logout button
  if (logoutButton) {
    logoutButton.addEventListener('click', function() {
      logout();
      if (userInfoContainer) {
        userInfoContainer.style.display = 'none';
      }
      if (loginContainer) {
        loginContainer.style.display = 'flex';
      }
    });
  }
  
  /**
   * Handle the callback from the OIDC provider
   */
  async function handleCallback() {
    try {
      const result = await handleOIDCCallback();
      if (result.success) {
        showUserInfo(result.user);
        // Redirect to the home page
        window.history.replaceState({}, document.title, '/');
      } else {
        showError(result.error || 'Authentication failed');
      }
    } catch (err) {
      showError(err.message || 'An error occurred during authentication');
    }
  }
  
  /**
   * Handle the authentication result
   * @param {Object} result - Authentication result
   */
  function handleAuthResult(result) {
    if (result.success) {
      showUserInfo(result.user);
    } else {
      showError(result.error || 'Authentication failed');
    }
  }
  
  /**
   * Show user information
   * @param {Object} user - User information
   */
  function showUserInfo(user) {
    if (loginContainer) {
      loginContainer.style.display = 'none';
    }
    
    if (userInfoContainer && userNameElement && userPhotoElement) {
      userNameElement.textContent = user.name || user.preferred_username || 'User';
      
      if (user.picture) {
        userPhotoElement.src = user.picture;
      } else {
        userPhotoElement.src = 'https://via.placeholder.com/80?text=User';
      }
      
      userInfoContainer.style.display = 'block';
    }
  }
  
  /**
   * Show an error message
   * @param {string} message - Error message
   */
  function showError(message) {
    if (errorContainer) {
      errorContainer.textContent = 'Error: ' + message;
      errorContainer.style.display = 'block';
    }
  }
}

// Export functions for use in HTML
window.initTelegramLoginWidget = initTelegramLoginWidget;
window.handleOIDCCallback = handleOIDCCallback;
window.isAuthenticated = isAuthenticated;
window.getCurrentUser = getCurrentUser;
window.logout = logout;
window.initTelegramLoginUI = initTelegramLoginUI;

// Initialize the UI when the DOM is loaded
document.addEventListener('DOMContentLoaded', initTelegramLoginUI);
