import { useState } from 'react';
import axios from 'axios';
import './index.css';

function App() {
  const [input, setInput] = useState('');
  const [hash, setHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleHash = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.post('http://localhost:3000/api/hash', {
        input,
      });
      setHash(response.data.hash);
    } catch (err) {
      setError('Error fetching hash from server.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center px-4">
      <div className="bg-white p-8 rounded-2xl shadow-md w-full max-w-xl space-y-4">
        <h1 className="text-2xl font-bold text-center text-gray-800">SHA-256 Visualizer</h1>

        <textarea
          className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
          rows={4}
          placeholder="Type your message here..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />

        <button
          onClick={handleHash}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 rounded-lg transition"
          disabled={loading}
        >
          {loading ? 'Encrypting...' : 'Encrypt with SHA-256'}
        </button>

        {error && <p className="text-red-500">{error}</p>}

        <div>
          <label className="block mb-2 font-semibold text-gray-700">Encrypted Output:</label>
          <textarea
            className="w-full p-3 border rounded-lg bg-gray-100 text-sm text-gray-800"
            rows={3}
            value={hash}
            readOnly
          />
        </div>
      </div>
    </div>
  );
}

export default App;
