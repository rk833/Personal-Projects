class CookieManager {
    constructor() {
        if (CookieManager.instance) {
            return CookieManager.instance;
        }
        CookieManager.instance = this;
        
        this.cookieBanner = null;
        this.initialized = false;
        console.log('CookieManager instance created');
    }

    init() {
        console.log('Init called, initialized:', this.initialized);
        if (this.initialized) return;
        
        const cookiePreference = this.getCookie('cookie_preferences_set');
        console.log('Cookie preference value:', cookiePreference);
        
        if (!cookiePreference || cookiePreference !== 'true') {
            console.log('No valid cookie preferences found, showing banner');
            this.showCookieBanner();
        } else {
            console.log('Cookie preferences already set, not showing banner');
        }
        
        this.initialized = true;
    }

    showCookieBanner() {
        console.log('Showing cookie banner');
        const banner = document.createElement('div');
        banner.className = 'cookie-banner';
        banner.innerHTML = `
            <div class="cookie-banner-content">
                <p class="cookie-banner-text">We use cookies to enhance your experience. By continuing to visit our site you agree to our use of cookies.</p>
                <div class="cookie-banner-buttons">
                    <button class="btn btn-primary" id="acceptAllCookies">Accept All</button>
                    <button class="btn btn-secondary" id="acceptEssentialCookies">Essential Only</button>
                    <a href="/cookie-policy" class="btn btn-link">Cookie Settings</a>
                </div>
            </div>
        `;
        document.body.appendChild(banner);
        this.cookieBanner = banner;

        // Fix: Add proper event listeners with bound context
        document.getElementById('acceptAllCookies').addEventListener('click', () => {
            this.acceptAll().then(() => {
                console.log('All cookies accepted');
                this.hideCookieBanner();
            }).catch(error => {
                console.error('Error accepting all cookies:', error);
            });
        });

        document.getElementById('acceptEssentialCookies').addEventListener('click', () => {
            this.acceptEssential().then(() => {
                console.log('Essential cookies accepted');
                this.hideCookieBanner();
            }).catch(error => {
                console.error('Error accepting essential cookies:', error);
            });
        });
    }

    async savePreferences(preferences) {
        console.log('Saving preferences:', preferences);
        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
            if (!csrfToken) {
                console.error('CSRF token not found');
                return false;
            }

            const response = await fetch('/save-cookie-preferences', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify(preferences),
                credentials: 'same-origin'
            });

            if (!response.ok) {
                console.error('Server response not OK:', response.status);
                return false;
            }

            console.log('Preferences saved successfully');
            return true;
        } catch (error) {
            console.error('Error saving preferences:', error);
            return false;
        }
    }

    async acceptAll() {
        const preferences = {
            essential: true,
            analytics: true,
            functional: true,
            marketing: true
        };
        const success = await this.savePreferences(preferences);
        if (success) {
            this.setCookie('cookie_preferences_set', 'true', 365);
            this.hideCookieBanner();
        } else {
            throw new Error('Failed to save cookie preferences');
        }
    }

    async acceptEssential() {
        const preferences = {
            essential: true,
            analytics: false,
            functional: false,
            marketing: false
        };
        const success = await this.savePreferences(preferences);
        if (success) {
            this.setCookie('cookie_preferences_set', 'true', 365);
            this.hideCookieBanner();
        } else {
            throw new Error('Failed to save cookie preferences');
        }
    }

    initializeFeatures() {
        const analytics = this.getCookie('analytics_cookies') === 'true';
        const marketing = this.getCookie('marketing_cookies') === 'true';
        const functional = this.getCookie('functional_cookies') === 'true';

        if (analytics) {
            this.initializeGoogleAnalytics();
        }

        if (marketing) {
            this.initializeMarketing();
        }

        if (functional) {
            this.initializeFunctional();
        }
    }

    // Helper methods
    setCookie(name, value, days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        const expires = "expires=" + date.toUTCString();
        document.cookie = `${name}=${value};${expires};path=/;SameSite=Lax`;
        console.log(`Cookie ${name} set with value ${value}`);
    }

    getCookie(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for(let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) == ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) == 0) {
                const value = c.substring(nameEQ.length, c.length);
                console.log(`Cookie ${name} found with value ${value}`);
                return value;
            }
        }
        console.log(`Cookie ${name} not found`);
        return null;
    }

    hideCookieBanner() {
        if (this.cookieBanner && this.cookieBanner.parentElement) {
            this.cookieBanner.remove();
            this.cookieBanner = null;
            console.log('Cookie banner hidden');
        }
    }

    // Feature initialization methods
    initializeGoogleAnalytics() {
        // Add your Google Analytics initialization code here
        console.log('Google Analytics initialized');
    }

    initializeMarketing() {
        // Add your marketing pixels initialization code here
        console.log('Marketing features initialized');
    }

    initializeFunctional() {
        // Add your functional features initialization code here
        console.log('Functional features initialized');
    }
}

// Create a single instance when the script loads
if (typeof window.cookieManager === 'undefined') {
    window.cookieManager = new CookieManager();
    document.addEventListener('DOMContentLoaded', () => {
        console.log('Initializing cookie manager...');
        try {
            window.cookieManager.init();
            console.log('Cookie manager initialized successfully');
        } catch (error) {
            console.error('Error initializing cookie manager:', error);
        }
    });
}