/* Copyright 2019 OSU OPEnS Lab
 * Modified 2026 for setInsecure() on ESP32-S2
 */

#include "Client.h"
#include "SSLSession.h"
#include "SSLClientParameters.h"
#include <vector>

#ifndef SSLClient_H_
#define SSLClient_H_

// --- ESTRUCTURA HELPER PARA INSECURE MODE ---
struct InsecureContext {
    const br_x509_class *vtable; 
    br_x509_decoder_context decoder; 
    bool is_server_cert; // <--- NUEVO: Para capturar solo el cert del servidor
};
// --------------------------------------------

class SSLClient : public Client {
public:
    enum Error {
        SSL_OK = 0,
        SSL_CLIENT_CONNECT_FAIL = 2,
        SSL_BR_CONNECT_FAIL = 3,
        SSL_CLIENT_WRTIE_ERROR = 4,
        SSL_BR_WRITE_ERROR = 5,
        SSL_INTERNAL_ERROR = 6,
        SSL_OUT_OF_MEMORY = 7
    };

    enum DebugLevel {
        SSL_NONE = 0,
        SSL_ERROR = 1,
        SSL_WARN = 2,
        SSL_INFO = 3,
        SSL_DUMP = 4,
    };

    explicit SSLClient( Client& client, 
                        const br_x509_trust_anchor *trust_anchors, 
                        const size_t trust_anchors_num, 
                        const int analog_pin, 
                        const size_t max_sessions = 1,
                        const size_t buffer_size = 2048, 
                        const DebugLevel debug = SSL_WARN);

    explicit SSLClient( Client& client, 
                const br_x509_trust_anchor *trust_anchors, 
                const size_t trust_anchors_num, 
                const int analog_pin, 
                const size_t max_sessions = 1,
                const DebugLevel debug = SSL_WARN)
        : SSLClient(client, trust_anchors, trust_anchors_num, analog_pin, max_sessions, 2048, debug)
    {
    }                       

    ~SSLClient();

    int connect(IPAddress ip, uint16_t port) override;
	int connect(const char *host, uint16_t port) override;
	size_t write(const uint8_t *buf, size_t size) override;
    size_t write(uint8_t b) override { return write(&b, 1); }
	int available() override;
	int read(uint8_t *buf, size_t size) override;
	int read() override { uint8_t read_val; return read(&read_val, 1) > 0 ? read_val : -1; };
    int peek() override;
	void flush() override;
	void stop() override;
	uint8_t connected() override;

    void setMutualAuthParams(const SSLClientParameters& params);
    SSLSession* getSession(const char* host);
    void removeSession(const char* host);
    size_t getSessionCount() const { return m_sessions.size(); }
	operator bool() { return connected() > 0; }
    Client& getClient() { return m_client; }
	void setTimeout(unsigned int t) { m_timeout = t; }
    unsigned int getTimeout() const { return m_timeout; }
    void setVerificationTime(uint32_t days, uint32_t seconds);

    void setInsecure();

private:
    Client& get_arduino_client() { return m_client; }
    const Client& get_arduino_client() const { return m_client; }

    bool m_soft_connected(const char* func_name);
    int m_start_ssl(const char* host = nullptr, SSLSession* ssl_ses = nullptr);
    int m_run_until(const unsigned target);
    unsigned m_update_engine();
    int m_get_session_index(const char* host) const; 

    void m_print_prefix(const char* func_name, const DebugLevel level) const;
    void m_print_ssl_error(const int ssl_error, const DebugLevel level) const;
    void m_print_br_error(const unsigned br_error_code, const DebugLevel level) const;
    void m_print_br_state(const unsigned br_state, const DebugLevel level) const;

    template<typename T>
    void m_print(const T str, const char* func_name, const DebugLevel level) const { 
        if (level > m_debug || !Serial) return;
        m_print_prefix(func_name, level);
        Serial.println(str);
    }

    template<typename T>
    void m_info(const T str, const char* func_name) const { m_print(str, func_name, SSL_INFO); }
    template<typename T>
    void m_warn(const T str, const char* func_name) const { m_print(str, func_name, SSL_WARN); }
    template<typename T>
    void m_error(const T str, const char* func_name) const { m_print(str, func_name, SSL_ERROR); }

    Client& m_client;
    std::vector<SSLSession> m_sessions;
    const size_t m_max_sessions;
    const int m_analog_pin;
    const DebugLevel m_debug;
    bool m_is_connected;
    unsigned int m_timeout;
    
    br_ssl_client_context m_sslctx;
    br_x509_minimal_context m_x509ctx;
    
    InsecureContext m_insecure_context;
    bool m_insecure_mode; 

    unsigned char* m_iobuf;
    size_t m_iobuf_size;
    size_t m_write_idx;
    unsigned m_br_last_state;
};

#endif /** SSLClient_H_ */