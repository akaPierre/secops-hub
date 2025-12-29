# SecOps Hub - Frontend

React-based dashboard for SecOps Hub security operations platform.

## Tech Stack

- **React 18** - UI framework
- **Vite** - Build tool and dev server
- **React Router** - Client-side routing
- **Tailwind CSS** - Utility-first CSS
- **Axios** - HTTP client
- **Recharts** - Data visualization
- **Lucide React** - Icon library

## Getting Started

### Install Dependencies

```bash
cd frontend
npm install
```

### Start Development Server

```bash
npm run dev
```

Frontend will run on: http://localhost:3000

### Build for Production

```bash
npm run build
```

## Project Structure

```
frontend/
├── src/
│   ├── components/       # Reusable components
│   │   ├── Layout.jsx   # Main layout with navigation
│   │   └── PrivateRoute.jsx
│   ├── context/          # React context providers
│   │   └── AuthContext.jsx
│   ├── pages/            # Page components
│   │   ├── Dashboard.jsx
│   │   ├── Login.jsx
│   │   ├── Register.jsx
│   │   ├── ThreatChecker.jsx
│   │   ├── CVESearch.jsx
│   │   └── ThreatList.jsx
│   ├── services/         # API services
│   │   └── api.js
│   ├── App.jsx          # Root component
│   ├── main.jsx         # Entry point
│   └── index.css        # Global styles
├── public/              # Static assets
├── index.html           # HTML template
├── vite.config.js       # Vite configuration
└── tailwind.config.js   # Tailwind configuration
```

## Features

- ✅ **Authentication** - Login/Register with JWT
- ✅ **Dashboard** - Overview with statistics
- ✅ **Threat Intelligence** - Multi-source threat checking
- ✅ **CVE Search** - Vulnerability database search
- ✅ **Responsive Design** - Mobile-friendly interface
- ✅ **Dark Theme** - Cybersecurity aesthetic

## Development

Make sure the backend API is running on port 5000.

```bash
# In backend directory
npm run dev
```

Then start the frontend:

```bash
# In frontend directory
npm run dev
```

## Environment Variables

The frontend automatically proxies `/api` requests to `http://localhost:5000` during development (configured in `vite.config.js`).

For production, set:

```bash
VITE_API_URL=https://your-api-domain.com
```
