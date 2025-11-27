import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Search, Download, Globe, Upload, FileCode } from 'lucide-react';

export default function VulnerabilityScanner() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [progress, setProgress] = useState(0);
  const [scanMode, setScanMode] = useState('url'); // 'url' or 'file'
  const [uploadedFile, setUploadedFile] = useState(null);
  const [fileContent, setFileContent] = useState('');

  const fileVulnerabilityChecks = [
    {
      name: 'Hardcoded Credentials',
      check: async (content) => {
        const issues = [];
        const patterns = [
          { regex: /password\s*=\s*["'][^"']+["']/gi, desc: 'Hardcoded password found' },
          { regex: /api[_-]?key\s*=\s*["'][^"']+["']/gi, desc: 'Hardcoded API key found' },
          { regex: /secret\s*=\s*["'][^"']+["']/gi, desc: 'Hardcoded secret found' },
          { regex: /token\s*=\s*["'][^"']+["']/gi, desc: 'Hardcoded token found' },
          { regex: /private[_-]?key\s*=\s*["'][^"']+["']/gi, desc: 'Private key found' }
        ];
        
        patterns.forEach(pattern => {
          const matches = content.match(pattern);
          if (matches) {
            issues.push(`${pattern.desc} (${matches.length} occurrence${matches.length > 1 ? 's' : ''})`);
          }
        });
        
        return {
          passed: issues.length === 0,
          issues: issues.length > 0 ? issues : ['No hardcoded credentials detected'],
          severity: 'high'
        };
      }
    },
    {
      name: 'SQL Injection Patterns',
      check: async (content) => {
        const issues = [];
        const patterns = [
          { regex: /SELECT\s+.*\s+FROM\s+.*WHERE.*\+/gi, desc: 'Potential SQL injection via string concatenation' },
          { regex: /execute\s*\(\s*["'].*\+/gi, desc: 'Dynamic SQL execution detected' },
          { regex: /query\s*\(\s*["'].*\+.*["']\s*\)/gi, desc: 'Unsafe query construction' }
        ];
        
        patterns.forEach(pattern => {
          if (pattern.regex.test(content)) {
            issues.push(pattern.desc);
          }
        });
        
        return {
          passed: issues.length === 0,
          issues: issues.length > 0 ? issues : ['No SQL injection patterns detected'],
          severity: 'high'
        };
      }
    },
    {
      name: 'XSS Vulnerabilities',
      check: async (content) => {
        const issues = [];
        const patterns = [
          { regex: /innerHTML\s*=\s*[^"']/gi, desc: 'Unsafe innerHTML assignment' },
          { regex: /document\.write\s*\(/gi, desc: 'Use of document.write (XSS risk)' },
          { regex: /eval\s*\(/gi, desc: 'Use of eval() function (XSS/Code injection risk)' },
          { regex: /dangerouslySetInnerHTML/gi, desc: 'Use of dangerouslySetInnerHTML in React' },
          { regex: /v-html\s*=/gi, desc: 'Use of v-html in Vue (XSS risk)' }
        ];
        
        patterns.forEach(pattern => {
          const matches = content.match(pattern);
          if (matches) {
            issues.push(`${pattern.desc} (${matches.length} occurrence${matches.length > 1 ? 's' : ''})`);
          }
        });
        
        return {
          passed: issues.length === 0,
          issues: issues.length > 0 ? issues : ['No XSS vulnerabilities detected'],
          severity: 'high'
        };
      }
    },
    {
      name: 'Insecure Dependencies',
      check: async (content) => {
        const issues = [];
        
        // Check for CDN links with no integrity attribute
        const cdnPattern = /<script[^>]+src=["'](https?:\/\/cdn[^"']+)["'][^>]*>/gi;
        const matches = content.matchAll(cdnPattern);
        
        for (const match of matches) {
          if (!match[0].includes('integrity=')) {
            issues.push(`CDN script without SRI integrity check: ${match[1]}`);
          }
        }
        
        // Check for HTTP CDN links
        const httpCdnPattern = /<script[^>]+src=["'](http:\/\/[^"']+)["']/gi;
        if (httpCdnPattern.test(content)) {
          issues.push('Insecure HTTP protocol used for script loading');
        }
        
        return {
          passed: issues.length === 0,
          issues: issues.length > 0 ? issues : ['No insecure dependency issues detected'],
          severity: 'medium'
        };
      }
    },
    {
      name: 'Sensitive Data Exposure',
      check: async (content) => {
        const issues = [];
        const patterns = [
          { regex: /console\.log\(/gi, desc: 'Console.log statements (may leak sensitive data)' },
          { regex: /debugger;/gi, desc: 'Debugger statements found' },
          { regex: /localhost|127\.0\.0\.1/gi, desc: 'Localhost references found' },
          { regex: /(test|debug|dev).*password/gi, desc: 'Test/debug credentials found' },
          { regex: /api\.example\.com/gi, desc: 'Example API endpoints found' }
        ];
        
        patterns.forEach(pattern => {
          const matches = content.match(pattern);
          if (matches && matches.length > 0) {
            issues.push(`${pattern.desc} (${matches.length} occurrence${matches.length > 1 ? 's' : ''})`);
          }
        });
        
        return {
          passed: issues.length === 0,
          issues: issues.length > 0 ? issues : ['No sensitive data exposure detected'],
          severity: 'medium'
        };
      }
    },
    {
      name: 'Insecure Cryptography',
      check: async (content) => {
        const issues = [];
        const patterns = [
          { regex: /md5\s*\(/gi, desc: 'MD5 hashing (cryptographically broken)' },
          { regex: /sha1\s*\(/gi, desc: 'SHA1 hashing (weak)' },
          { regex: /Math\.random\(\)/gi, desc: 'Math.random() used (not cryptographically secure)' },
          { regex: /btoa\(/gi, desc: 'Base64 encoding (not encryption)' }
        ];
        
        patterns.forEach(pattern => {
          if (pattern.regex.test(content)) {
            issues.push(pattern.desc);
          }
        });
        
        return {
          passed: issues.length === 0,
          issues: issues.length > 0 ? issues : ['No insecure cryptography detected'],
          severity: 'medium'
        };
      }
    },
    {
      name: 'Outdated Libraries',
      check: async (content) => {
        const issues = [];
        const outdated = [
          { pattern: /jquery@1\./gi, desc: 'jQuery 1.x (outdated, security vulnerabilities)' },
          { pattern: /angular@1\./gi, desc: 'AngularJS 1.x (end of life)' },
          { pattern: /react@15\./gi, desc: 'React 15.x (outdated)' },
          { pattern: /bootstrap@3\./gi, desc: 'Bootstrap 3.x (outdated)' }
        ];
        
        outdated.forEach(item => {
          if (item.pattern.test(content)) {
            issues.push(item.desc);
          }
        });
        
        return {
          passed: issues.length === 0,
          issues: issues.length > 0 ? issues : ['No outdated libraries detected in code'],
          severity: 'low'
        };
      }
    },
    {
      name: 'CORS Misconfigurations',
      check: async (content) => {
        const issues = [];
        
        if (/Access-Control-Allow-Origin:\s*\*/gi.test(content)) {
          issues.push('Wildcard CORS policy detected (Access-Control-Allow-Origin: *)');
        }
        
        if (/Access-Control-Allow-Credentials:\s*true/gi.test(content) && 
            /Access-Control-Allow-Origin:\s*\*/gi.test(content)) {
          issues.push('Dangerous CORS config: credentials with wildcard origin');
        }
        
        return {
          passed: issues.length === 0,
          issues: issues.length > 0 ? issues : ['No CORS misconfigurations detected'],
          severity: 'high'
        };
      }
    }
  ];

  const vulnerabilityChecks = [
    {
      name: 'SSL/TLS Security',
      check: async (targetUrl) => {
        const issues = [];
        if (!targetUrl.startsWith('https://')) {
          issues.push('Site does not use HTTPS encryption');
        }
        return {
          passed: targetUrl.startsWith('https://'),
          issues,
          severity: 'high'
        };
      }
    },
    {
      name: 'Security Headers',
      check: async (targetUrl) => {
        try {
          const response = await fetch(targetUrl, { method: 'HEAD' });
          const headers = response.headers;
          const issues = [];
          
          if (!headers.get('strict-transport-security')) {
            issues.push('Missing Strict-Transport-Security header');
          }
          if (!headers.get('x-frame-options')) {
            issues.push('Missing X-Frame-Options header (Clickjacking protection)');
          }
          if (!headers.get('x-content-type-options')) {
            issues.push('Missing X-Content-Type-Options header');
          }
          if (!headers.get('content-security-policy')) {
            issues.push('Missing Content-Security-Policy header');
          }
          if (!headers.get('x-xss-protection')) {
            issues.push('Missing X-XSS-Protection header');
          }
          
          return {
            passed: issues.length === 0,
            issues,
            severity: 'medium'
          };
        } catch (e) {
          return {
            passed: false,
            issues: ['Unable to check security headers - CORS or network error'],
            severity: 'low'
          };
        }
      }
    },
    {
      name: 'Cookie Security',
      check: async (targetUrl) => {
        const issues = [];
        try {
          const response = await fetch(targetUrl);
          const cookies = response.headers.get('set-cookie') || '';
          
          if (cookies) {
            if (!cookies.includes('Secure')) {
              issues.push('Cookies not marked as Secure');
            }
            if (!cookies.includes('HttpOnly')) {
              issues.push('Cookies not marked as HttpOnly');
            }
            if (!cookies.includes('SameSite')) {
              issues.push('Cookies missing SameSite attribute');
            }
          }
          
          return {
            passed: issues.length === 0,
            issues: issues.length > 0 ? issues : ['Cookie security attributes properly configured'],
            severity: 'medium'
          };
        } catch (e) {
          return {
            passed: false,
            issues: ['Unable to check cookies - CORS restriction'],
            severity: 'low'
          };
        }
      }
    },
    {
      name: 'Mixed Content',
      check: async (targetUrl) => {
        const issues = [];
        if (targetUrl.startsWith('https://')) {
          try {
            const response = await fetch(targetUrl);
            const html = await response.text();
            
            const httpResources = html.match(/http:\/\/[^"'\s]+/g) || [];
            if (httpResources.length > 0) {
              issues.push(`Found ${httpResources.length} insecure HTTP resources on HTTPS page`);
            }
            
            return {
              passed: httpResources.length === 0,
              issues: issues.length > 0 ? issues : ['No mixed content detected'],
              severity: 'medium'
            };
          } catch (e) {
            return {
              passed: false,
              issues: ['Unable to check for mixed content - CORS restriction'],
              severity: 'low'
            };
          }
        }
        return {
          passed: false,
          issues: ['Site not using HTTPS'],
          severity: 'high'
        };
      }
    },
    {
      name: 'Information Disclosure',
      check: async (targetUrl) => {
        const issues = [];
        try {
          const response = await fetch(targetUrl);
          const serverHeader = response.headers.get('server');
          const poweredBy = response.headers.get('x-powered-by');
          
          if (serverHeader) {
            issues.push(`Server header exposes: ${serverHeader}`);
          }
          if (poweredBy) {
            issues.push(`X-Powered-By header exposes: ${poweredBy}`);
          }
          
          return {
            passed: issues.length === 0,
            issues: issues.length > 0 ? issues : ['No obvious information disclosure'],
            severity: 'low'
          };
        } catch (e) {
          return {
            passed: false,
            issues: ['Unable to check headers - CORS restriction'],
            severity: 'low'
          };
        }
      }
    },
    {
      name: 'Common Vulnerability Patterns',
      check: async (targetUrl) => {
        const issues = [];
        try {
          const response = await fetch(targetUrl);
          const html = await response.text();
          
          // Check for potential XSS vulnerabilities
          if (html.includes('eval(') || html.includes('innerHTML')) {
            issues.push('Potentially dangerous JavaScript patterns detected');
          }
          
          // Check for exposed sensitive paths
          const sensitivePaths = ['/admin', '/.git', '/.env', '/config'];
          for (const path of sensitivePaths) {
            if (html.includes(path)) {
              issues.push(`Potential exposure of sensitive path: ${path}`);
            }
          }
          
          return {
            passed: issues.length === 0,
            issues: issues.length > 0 ? issues : ['No common vulnerability patterns detected'],
            severity: 'medium'
          };
        } catch (e) {
          return {
            passed: false,
            issues: ['Unable to analyze content - CORS restriction'],
            severity: 'low'
          };
        }
      }
    }
  ];

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      setUploadedFile(file);
      const reader = new FileReader();
      reader.onload = (event) => {
        setFileContent(event.target.result);
      };
      reader.readAsText(file);
    }
  };

  const scanFile = async () => {
    if (!fileContent) return;
    
    setScanning(true);
    setProgress(0);
    setResults(null);

    const scanResults = [];
    const total = fileVulnerabilityChecks.length;

    for (let i = 0; i < fileVulnerabilityChecks.length; i++) {
      const check = fileVulnerabilityChecks[i];
      try {
        const result = await check.check(fileContent);
        scanResults.push({
          name: check.name,
          ...result
        });
      } catch (error) {
        scanResults.push({
          name: check.name,
          passed: false,
          issues: ['Scan failed: ' + error.message],
          severity: 'low'
        });
      }
      setProgress(((i + 1) / total) * 100);
      await new Promise(resolve => setTimeout(resolve, 300));
    }

    setResults({
      url: uploadedFile.name,
      timestamp: new Date().toISOString(),
      checks: scanResults,
      summary: {
        total: scanResults.length,
        passed: scanResults.filter(r => r.passed).length,
        failed: scanResults.filter(r => !r.passed).length,
        high: scanResults.filter(r => r.severity === 'high' && !r.passed).length,
        medium: scanResults.filter(r => r.severity === 'medium' && !r.passed).length,
        low: scanResults.filter(r => r.severity === 'low' && !r.passed).length
      }
    });

    setScanning(false);
  };

  const scanWebsite = async () => {
    if (!url) return;
    
    setScanning(true);
    setProgress(0);
    setResults(null);

    let targetUrl = url;
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
    }

    const scanResults = [];
    const total = vulnerabilityChecks.length;

    for (let i = 0; i < vulnerabilityChecks.length; i++) {
      const check = vulnerabilityChecks[i];
      try {
        const result = await check.check(targetUrl);
        scanResults.push({
          name: check.name,
          ...result
        });
      } catch (error) {
        scanResults.push({
          name: check.name,
          passed: false,
          issues: ['Scan failed: ' + error.message],
          severity: 'low'
        });
      }
      setProgress(((i + 1) / total) * 100);
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    setResults({
      url: targetUrl,
      timestamp: new Date().toISOString(),
      checks: scanResults,
      summary: {
        total: scanResults.length,
        passed: scanResults.filter(r => r.passed).length,
        failed: scanResults.filter(r => !r.passed).length,
        high: scanResults.filter(r => r.severity === 'high' && !r.passed).length,
        medium: scanResults.filter(r => r.severity === 'medium' && !r.passed).length,
        low: scanResults.filter(r => r.severity === 'low' && !r.passed).length
      }
    });

    setScanning(false);
  };

  const downloadReport = () => {
    if (!results) return;
    
    const report = `Web Vulnerability Scan Report
${'-'.repeat(50)}
URL: ${results.url}
Scan Date: ${new Date(results.timestamp).toLocaleString()}

SUMMARY
${'-'.repeat(50)}
Total Checks: ${results.summary.total}
Passed: ${results.summary.passed}
Failed: ${results.summary.failed}
  - High Severity: ${results.summary.high}
  - Medium Severity: ${results.summary.medium}
  - Low Severity: ${results.summary.low}

DETAILED RESULTS
${'-'.repeat(50)}
${results.checks.map(check => `
${check.name}
Status: ${check.passed ? 'PASSED' : 'FAILED'}
Severity: ${check.severity.toUpperCase()}
Issues:
${check.issues.map(issue => `  - ${issue}`).join('\n')}
`).join('\n')}
`;

    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability-scan-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'high': return 'text-red-600 bg-red-50';
      case 'medium': return 'text-orange-600 bg-orange-50';
      case 'low': return 'text-yellow-600 bg-yellow-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-xl shadow-2xl p-8 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-10 h-10 text-blue-600" />
            <div>
              <h1 className="text-3xl font-bold text-gray-800">Web Vulnerability Scanner</h1>
              <p className="text-gray-600">Identify security vulnerabilities in websites</p>
            </div>
          </div>

          {/* Scan Input */}
          <div className="mb-6">
            {/* Mode Selector */}
            <div className="flex gap-2 mb-4">
              <button
                onClick={() => setScanMode('url')}
                className={`flex-1 py-2 px-4 rounded-lg font-semibold flex items-center justify-center gap-2 transition-colors ${
                  scanMode === 'url' 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                <Globe className="w-5 h-5" />
                Scan URL
              </button>
              <button
                onClick={() => setScanMode('file')}
                className={`flex-1 py-2 px-4 rounded-lg font-semibold flex items-center justify-center gap-2 transition-colors ${
                  scanMode === 'file' 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                <Upload className="w-5 h-5" />
                Upload File
              </button>
            </div>

            {/* URL Mode */}
            {scanMode === 'url' && (
              <div className="flex gap-3">
                <div className="flex-1 relative">
                  <Globe className="absolute left-3 top-3.5 w-5 h-5 text-gray-400" />
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && scanWebsite()}
                    placeholder="Enter website URL (e.g., example.com)"
                    className="w-full pl-10 pr-4 py-3 border-2 border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                    disabled={scanning}
                  />
                </div>
                <button
                  onClick={scanWebsite}
                  disabled={scanning || !url}
                  className="px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center gap-2 transition-colors"
                >
                  <Search className="w-5 h-5" />
                  {scanning ? 'Scanning...' : 'Scan'}
                </button>
              </div>
            )}

            {/* File Mode */}
            {scanMode === 'file' && (
              <div className="space-y-3">
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-500 transition-colors">
                  <input
                    type="file"
                    id="file-upload"
                    accept=".html,.htm,.js,.jsx,.ts,.tsx,.php,.json,.xml,.config"
                    onChange={handleFileUpload}
                    className="hidden"
                    disabled={scanning}
                  />
                  <label htmlFor="file-upload" className="cursor-pointer">
                    <FileCode className="w-12 h-12 text-gray-400 mx-auto mb-3" />
                    {uploadedFile ? (
                      <div>
                        <p className="text-lg font-semibold text-gray-700">{uploadedFile.name}</p>
                        <p className="text-sm text-gray-500">Click to change file</p>
                      </div>
                    ) : (
                      <div>
                        <p className="text-lg font-semibold text-gray-700">Click to upload file</p>
                        <p className="text-sm text-gray-500">HTML, JS, PHP, JSON, XML, Config files</p>
                      </div>
                    )}
                  </label>
                </div>
                <button
                  onClick={scanFile}
                  disabled={scanning || !uploadedFile}
                  className="w-full px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-colors"
                >
                  <Search className="w-5 h-5" />
                  {scanning ? 'Scanning...' : 'Scan File'}
                </button>
              </div>
            )}
          </div>

          {/* Progress Bar */}
          {scanning && (
            <div className="mt-4">
              <div className="w-full bg-gray-200 rounded-full h-3">
                <div
                  className="bg-blue-600 h-3 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <p className="text-sm text-gray-600 mt-2 text-center">
                Scanning... {Math.round(progress)}%
              </p>
            </div>
          )}
        </div>

        {/* Results */}
        {results && (
          <div className="bg-white rounded-xl shadow-2xl p-8">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
              <div className="bg-blue-50 rounded-lg p-4 text-center">
                <p className="text-3xl font-bold text-blue-600">{results.summary.total}</p>
                <p className="text-sm text-gray-600">Total Checks</p>
              </div>
              <div className="bg-green-50 rounded-lg p-4 text-center">
                <p className="text-3xl font-bold text-green-600">{results.summary.passed}</p>
                <p className="text-sm text-gray-600">Passed</p>
              </div>
              <div className="bg-red-50 rounded-lg p-4 text-center">
                <p className="text-3xl font-bold text-red-600">{results.summary.high}</p>
                <p className="text-sm text-gray-600">High Risk</p>
              </div>
              <div className="bg-orange-50 rounded-lg p-4 text-center">
                <p className="text-3xl font-bold text-orange-600">{results.summary.medium}</p>
                <p className="text-sm text-gray-600">Medium Risk</p>
              </div>
              <div className="bg-yellow-50 rounded-lg p-4 text-center">
                <p className="text-3xl font-bold text-yellow-600">{results.summary.low}</p>
                <p className="text-sm text-gray-600">Low Risk</p>
              </div>
            </div>

            {/* Download Button */}
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold text-gray-800">Detailed Results</h2>
              <button
                onClick={downloadReport}
                className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center gap-2 transition-colors"
              >
                <Download className="w-4 h-4" />
                Download Report
              </button>
            </div>

            {/* Vulnerability List */}
            <div className="space-y-4">
              {results.checks.map((check, index) => (
                <div
                  key={index}
                  className={`border-2 rounded-lg p-4 ${
                    check.passed ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'
                  }`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      {check.passed ? (
                        <CheckCircle className="w-6 h-6 text-green-600 flex-shrink-0" />
                      ) : (
                        <XCircle className="w-6 h-6 text-red-600 flex-shrink-0" />
                      )}
                      <h3 className="text-lg font-semibold text-gray-800">{check.name}</h3>
                    </div>
                    {!check.passed && (
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(check.severity)}`}>
                        {check.severity.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <div className="ml-9">
                    {check.issues.map((issue, i) => (
                      <div key={i} className="flex items-start gap-2 mb-1">
                        <AlertTriangle className={`w-4 h-4 mt-0.5 flex-shrink-0 ${
                          check.passed ? 'text-green-600' : 'text-red-600'
                        }`} />
                        <p className="text-sm text-gray-700">{issue}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {/* Disclaimer */}
            <div className="mt-8 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
              <p className="text-sm text-gray-700">
                <strong>Note:</strong> This scanner performs basic security checks and may be limited by CORS policies. 
                For comprehensive security assessments, consider using professional tools like OWASP ZAP, Burp Suite, or Nmap.
                Some checks may return "CORS restriction" errors when scanning external websites due to browser security policies.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}