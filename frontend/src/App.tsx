import { useState } from 'react';
import axios from 'axios';
import './index.css';

interface TraceRound {
  round: number;
  inputHashOutputs: string[];
  computedNewIV: string;
  newBlocks: string[];
  outputHashOutputs: string[];
}

interface Trace {
  originalMessage: string;
  padded: string;
  blocks: string[];
  initialHashOutputs: string[];
  rounds: TraceRound[];
  finalDigest: string;
}

interface ApiResponse {
  finalDigest: string;
  trace: Trace;
  normalHash: string;
}

function App() {
  const [input, setInput] = useState('');
  const [hash, setHash] = useState('');
  const [normalHash, setNormalHash] = useState('');
  const [trace, setTrace] = useState<Trace | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [expandedRounds, setExpandedRounds] = useState<number[]>([]);

  const handleHash = async () => {
    setLoading(true);
    setError('');
    setTrace(null);
    try {
      const response = await axios.post<ApiResponse>('http://localhost:3000/api/hash', {
        input,
      });
      setHash(response.data.finalDigest);
      setNormalHash(response.data.normalHash);
      setTrace(response.data.trace);
    } catch (err) {
      console.error("Error fetching hash:", err);
      setError('Error fetching hash from server.');
    } finally {
      setLoading(false);
    }
  };

  const toggleRound = (idx: number) => {
    setExpandedRounds((prev) =>
      prev.includes(idx) ? prev.filter((r) => r !== idx) : [...prev, idx]
    );
  };

  return (
    <div className="min-h-screen bg-gray-50 py-10 px-4 flex flex-col items-center text-gray-800">
      <div className="bg-white w-full max-w-3xl p-8 rounded-2xl shadow-xl space-y-6">
        <h1 className="text-4xl font-bold text-center text-blue-700">SHA-256 Parallel Visualizer</h1>

        <textarea
          className="w-full p-4 border rounded-lg text-lg focus:ring-2 focus:ring-blue-400"
          placeholder="Type your message..."
          rows={3}
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />

        <button
          onClick={handleHash}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-xl transition disabled:opacity-50"
          disabled={loading}
        >
          {loading ? 'Encrypting...' : 'Run Custom SHA-256'}
        </button>

        {error && <div className="text-red-600 font-medium">{error}</div>}

        {hash && (
          <div className="space-y-3 text-sm">
            <div>
              <label className="font-semibold">🔒 Custom SHA-256 Digest:</label>
              <code className="block bg-gray-100 p-3 mt-1 rounded break-all">{hash}</code>
            </div>
            <div>
              <label className="font-semibold">⚙️ Standard SHA-256 Digest:</label>
              <code className="block bg-gray-100 p-3 mt-1 rounded break-all">{normalHash}</code>
            </div>
          </div>
        )}
      </div>

      {trace && (
        <div className="mt-8 bg-white w-full max-w-3xl p-8 rounded-2xl shadow-md space-y-6">
          <h2 className="text-2xl font-bold text-gray-700">🔍 Trace Visualization</h2>

          <div>
            <strong>📨 Original Message:</strong>
            <pre className="bg-gray-100 p-3 rounded text-sm">{trace.originalMessage}</pre>
          </div>
          <div>
            <strong>📦 Padded Message (hex):</strong>
            <pre className="bg-gray-100 p-3 rounded text-xs overflow-x-auto">{trace.padded}</pre>
          </div>
          <div>
            <strong>📚 Initial Blocks (512-bit):</strong>
            {trace.blocks.map((blk, idx) => (
              <pre key={idx} className="bg-gray-100 p-3 rounded text-xs mb-2 overflow-x-auto">
                Block {idx}: {blk}
              </pre>
            ))}
          </div>
          <div>
            <strong>🔧 Initial Hash Outputs (256-bit):</strong>
            {trace.initialHashOutputs.map((ho, idx) => (
              <pre key={idx} className="bg-gray-100 p-2 rounded text-xs mb-1 overflow-x-auto">
                Block {idx}: {ho}
              </pre>
            ))}
          </div>

          <div>
            <strong>🔁 Reduction Rounds:</strong>
            {trace.rounds.map((round, idx) => (
              <div key={idx} className="mt-4 border rounded-md">
                <button
                  className="w-full text-left px-4 py-2 bg-blue-100 hover:bg-blue-200 font-semibold rounded-t"
                  onClick={() => toggleRound(idx)}
                >
                  {expandedRounds.includes(idx) ? '▼' : '▶'} Round {round.round}
                </button>
                {expandedRounds.includes(idx) && (
                  <div className="p-4 space-y-2 text-xs">
                    <div>
                      <strong>Input Hash Outputs:</strong>
                      {round.inputHashOutputs.map((val, i) => (
                        <pre key={i} className="bg-gray-100 p-2 rounded overflow-x-auto">{val}</pre>
                      ))}
                    </div>
                    <div>
                      <strong>Computed New IV:</strong>
                      <pre className="bg-gray-100 p-2 rounded overflow-x-auto">{round.computedNewIV}</pre>
                    </div>
                    <div>
                      <strong>New Blocks (concatenated):</strong>
                      {round.newBlocks.map((blk, i) => (
                        <pre key={i} className="bg-gray-100 p-2 rounded overflow-x-auto">{blk}</pre>
                      ))}
                    </div>
                    <div>
                      <strong>Output Hash Outputs:</strong>
                      {round.outputHashOutputs.map((val, i) => (
                        <pre key={i} className="bg-gray-100 p-2 rounded overflow-x-auto">{val}</pre>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div>
            <strong>✅ Final Custom Digest:</strong>
            <pre className="bg-green-100 text-green-900 p-3 rounded text-sm overflow-x-auto font-mono">
              {trace.finalDigest}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
