/* Copyright 2019 OSU OPEnS Lab
 * Modified 2026 for setInsecure() logic fix
 */

#include "SSLClient.h"

// ============================================================================
// IMPLEMENTACIÓN INSEGURA CORREGIDA (SOLO DECODIFICA EL PRIMER CERT)
// ============================================================================

static void insecure_start_chain(const br_x509_class **ctx, const char *server_name) {
    InsecureContext *ic = (InsecureContext *)ctx;
    // Preparamos para recibir la cadena. El primero siempre es el del servidor.
    ic->is_server_cert = true;
}

static void insecure_start_cert(const br_x509_class **ctx, uint32_t length) {
    InsecureContext *ic = (InsecureContext *)ctx;
    // Solo inicializamos el decoder si es el certificado del servidor (el primero)
    if (ic->is_server_cert) {
        br_x509_decoder_init(&ic->decoder, 0, 0);
    }
}

static void insecure_append(const br_x509_class **ctx, const unsigned char *buf, size_t len) {
    InsecureContext *ic = (InsecureContext *)ctx;
    // Solo alimentamos datos si es el certificado del servidor
    if (ic->is_server_cert) {
        br_x509_decoder_push(&ic->decoder, buf, len);
    }
}

static void insecure_end_cert(const br_x509_class **ctx) {
    InsecureContext *ic = (InsecureContext *)ctx;
    // Una vez terminado el primer certificado, marcamos flag a falso.
    // Los siguientes certificados (intermedios/root) serán ignorados por append.
    if (ic->is_server_cert) {
        ic->is_server_cert = false;
        
        // Opcional: Verificar si el decoder falló, pero en modo inseguro asumimos que queremos seguir.
        // int err = br_x509_decoder_last_error(&ic->decoder);
    }
}

static unsigned insecure_end_chain(const br_x509_class **ctx) {
    // Retornamos 0 (OK) incondicionalmente.
    return 0; 
}

static const br_x509_pkey *insecure_get_pkey(const br_x509_class *const *ctx, unsigned *usages) {
    InsecureContext *ic = (InsecureContext *)ctx;
    if (usages) {
        *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
    }
    // Retornamos la clave pública extraída del PRIMER certificado
    return br_x509_decoder_get_pkey(&ic->decoder);
}

static const br_x509_class insecure_vtable = {
    sizeof(InsecureContext),
    insecure_start_chain,
    insecure_start_cert,
    insecure_append,
    insecure_end_cert,
    insecure_end_chain,
    insecure_get_pkey
};

// ============================================================================


SSLClient::SSLClient(   Client& client, 
                        const br_x509_trust_anchor *trust_anchors, 
                        const size_t trust_anchors_num, 
                        const int analog_pin, 
                        const size_t max_sessions,
                        const size_t buffer_size,
                        const DebugLevel debug)
: m_client(client) 
    , m_sessions()
    , m_max_sessions(max_sessions)
    , m_analog_pin(analog_pin)       // <-- Movido hacia arriba para coincidir con el .h
    , m_debug(debug)
    , m_is_connected(false)
    , m_timeout(30000)
    , m_insecure_mode(false)
    , m_iobuf(nullptr)               // <-- Movido hacia abajo
    , m_iobuf_size(buffer_size)      // <-- Movido hacia abajo
    , m_write_idx(0)
    , m_br_last_state(0) {

    setTimeout(30*1000);
    m_iobuf = new unsigned char[m_iobuf_size];
    memset(m_iobuf, 0, m_iobuf_size);
    
    br_client_init_TLS12_only(&m_sslctx, &m_x509ctx, trust_anchors, trust_anchors_num);
    
    // Conectar vtable
    m_insecure_context.vtable = &insecure_vtable;
    m_insecure_context.is_server_cert = false;

    const auto duplex = m_iobuf_size <= BR_SSL_BUFSIZE_MONO ? 0 : 1;
    br_ssl_engine_set_buffer(&m_sslctx.eng, m_iobuf, m_iobuf_size, duplex);
}

SSLClient::~SSLClient() {
    if (m_iobuf) delete[] m_iobuf;
}

void SSLClient::setInsecure() {
    m_insecure_mode = true;
}

int SSLClient::connect(IPAddress ip, uint16_t port) {
    const char* func_name = __func__;
    if (get_arduino_client().connected())
        m_warn("Arduino client is already connected? Continuing anyway...", func_name);
    m_write_idx = 0;
    m_warn("Using a raw IP Address bypasses verification.", func_name);
    if (!get_arduino_client().connect(ip, port)) {
        m_error("Failed to connect using m_client.", func_name);
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    m_info("Base client connected!", func_name);
    return m_start_ssl(nullptr);
}

int SSLClient::connect(const char *host, uint16_t port) {
    const char* func_name = __func__;
    if (get_arduino_client().connected())
        m_warn("Arduino client is already connected? Continuing anyway...", func_name);
    m_write_idx = 0;
    if (!get_arduino_client().connect(host, port)) {
        m_error("Failed to connect using m_client.", func_name);
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    m_info("Base client connected!", func_name);
    return m_start_ssl(host, getSession(host));
}

size_t SSLClient::write(const uint8_t *buf, size_t size) {
    const char* func_name = __func__;
    if (m_debug >= DebugLevel::SSL_DUMP) Serial.write(buf, size);
    if (!m_soft_connected(func_name) || !buf || !size) return 0;
    if (m_run_until(BR_SSL_SENDAPP) < 0) {
        m_error("Failed while waiting for engine (SENDAPP)", func_name);
        return 0;
    }
    size_t alen;
    unsigned char *br_buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
    size_t cur_idx = 0;
    if (alen == 0) {
        m_error("BearSSL returned zero length buffer", func_name);
        return 0;
    }
    while (cur_idx < size) {
        const size_t cpamount = size - cur_idx >= alen - m_write_idx ? alen - m_write_idx : size - cur_idx;
        memcpy(br_buf + m_write_idx, buf + cur_idx, cpamount);
        m_write_idx += cpamount;
        cur_idx += cpamount;
        if(m_write_idx == alen) {
            br_ssl_engine_sendapp_ack(&m_sslctx.eng, m_write_idx);
            m_write_idx = 0;
            if (m_run_until(BR_SSL_SENDAPP) < 0) {
                m_error("Failed while waiting for engine (SENDAPP loop)", func_name);
                return 0;
            }
            br_buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
        }
    } 
    return size;
}

int SSLClient::available() {
    const char* func_name = __func__;
    if (!m_soft_connected(func_name)) return 0;
    unsigned state = m_update_engine();
    if (state == 0) m_error("SSL engine failed to update.", func_name);
    else if(state & BR_SSL_RECVAPP) {
        size_t alen;
        br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen);
        return (int)(alen);
    }
    else if (state == BR_SSL_CLOSED) m_info("Engine closed after update", func_name);
    else if (state & BR_SSL_SENDAPP) br_ssl_engine_flush(&m_sslctx.eng, 0);
    return 0;
}

int SSLClient::read(uint8_t *buf, size_t size) {
    if (available() <= 0 || !size) return -1;
    size_t alen;
    unsigned char* br_buf = br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen);
    const size_t read_amount = size > alen ? alen : size;
    if(buf) memcpy(buf, br_buf, read_amount);
    br_ssl_engine_recvapp_ack(&m_sslctx.eng, read_amount);
    return read_amount;
}

int SSLClient::peek() {
    if (available() <= 0) return -1; 
    size_t alen;
    uint8_t read_num;
    read_num = br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen)[0];
    return (int)read_num;
}

void SSLClient::flush() {
    if (m_write_idx > 0) {
        if(m_run_until(BR_SSL_RECVAPP) < 0) {
            m_error("Could not flush write buffer!", __func__);
            int error = br_ssl_engine_last_error(&m_sslctx.eng);
            if(error != BR_ERR_OK) 
                m_print_br_error(error, SSL_ERROR);
            if (getWriteError()) 
                m_print_ssl_error(getWriteError(), SSL_ERROR);
        }
    }
}

void SSLClient::stop() {
    auto state = br_ssl_engine_current_state(&m_sslctx.eng);
    if (state != BR_SSL_CLOSED
        && state != 0
        && connected()) {
		size_t len;
		if (br_ssl_engine_recvapp_buf(&m_sslctx.eng, &len) != nullptr) {
			br_ssl_engine_recvapp_ack(&m_sslctx.eng, len);
		}
        flush();
	}
    get_arduino_client().flush();
    get_arduino_client().stop();
    m_is_connected = false;
}

uint8_t SSLClient::connected() {
    const char* func_name = __func__;
    const auto c_con = get_arduino_client().connected();
    const auto br_con = br_ssl_engine_current_state(&m_sslctx.eng) != BR_SSL_CLOSED && m_is_connected;
    const auto wr_ok = getWriteError() == 0;
    if (br_con && !c_con) {
        if (get_arduino_client().getWriteError()) {
            m_error("Socket interrupted. m_client error: ", func_name);
            m_error(get_arduino_client().getWriteError(), func_name);
            setWriteError(SSL_CLIENT_WRTIE_ERROR);
        }
        else {
            m_warn("Socket dropped unexpectedly", func_name);
        }
        m_is_connected = false;
        stop();
    }
    else if (!wr_ok) {
        m_error("Not connected because write error is set", func_name);
        m_print_ssl_error(getWriteError(), SSL_ERROR);
    }
    return c_con && br_con;
}

SSLSession* SSLClient::getSession(const char* host) {
    const char* func_name = __func__;
    int temp_index = m_get_session_index(host);
    if (temp_index < 0) return nullptr;
    m_info("Using session index: ", func_name);
    m_info(temp_index, func_name);
    return &(m_sessions[temp_index]);
}

void SSLClient::removeSession(const char* host) {
    const char* func_name = __func__;
    int temp_index = m_get_session_index(host);
    if (temp_index >= 0) {
        m_info(" Deleted session ", func_name);
        m_info(temp_index, func_name);
        m_sessions.erase(m_sessions.begin() + static_cast<size_t>(temp_index));
    }
}

void SSLClient::setMutualAuthParams(const SSLClientParameters& params) {
    if (params.getECKey() != NULL) {
        br_ssl_client_set_single_ec(    &m_sslctx,
                                        params.getCertChain(),
                                        1,
                                        params.getECKey(),
                                        BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
                                        BR_KEYTYPE_EC,
                                        br_ssl_engine_get_ec(&m_sslctx.eng),
                                        &br_ecdsa_i15_sign_asn1);
    }
    else if (params.getRSAKey() != NULL) {
        br_ssl_client_set_single_rsa(   &m_sslctx,
                                        params.getCertChain(),
                                        1,
                                        params.getRSAKey(),
                                        &br_rsa_i15_pkcs1_sign);
    }
}

void SSLClient::setVerificationTime(uint32_t days, uint32_t seconds) {
    br_x509_minimal_set_time(&m_x509ctx, days, seconds);
}

bool SSLClient::m_soft_connected(const char* func_name) {
    if (getWriteError()) {
        m_error("Cannot operate if the write error is not reset: ", func_name); 
        m_print_ssl_error(getWriteError(), SSL_ERROR);
        return false;
    }
    if(!m_is_connected || br_ssl_engine_current_state(&m_sslctx.eng) == BR_SSL_CLOSED) {
        m_error("Cannot operate on a closed SSL connection.", func_name);
        int error = br_ssl_engine_last_error(&m_sslctx.eng);
        if(error != BR_ERR_OK) m_print_br_error(error, SSL_ERROR);   
        return false;
    }
    return true;
}

int SSLClient::m_start_ssl(const char* host, SSLSession* ssl_ses) {
    const char* func_name = __func__;
    setWriteError(SSL_OK);
    uint8_t rng_seeds[16];
    for (uint8_t i = 0; i < sizeof rng_seeds; i++) {
        if (m_analog_pin >= 0) {
            // Comportamiento original si se define un pin válido
            rng_seeds[i] = static_cast<uint8_t>(analogRead(m_analog_pin));
        } else {
            // Si el pin es -1, usamos una alternativa mejor
#if defined(ESP32)
            // Generador de hardware real del ESP32 (Muy recomendado para SSL)
            rng_seeds[i] = static_cast<uint8_t>(esp_random() & 0xFF);
#else
            // Fallback genérico para otras placas (Arduino, etc.)
            rng_seeds[i] = static_cast<uint8_t>(random(256));
#endif
        }
    }
    br_ssl_engine_inject_entropy(&m_sslctx.eng, rng_seeds, sizeof rng_seeds);
    if(ssl_ses != nullptr) {
        br_ssl_engine_set_session_parameters(&m_sslctx.eng, ssl_ses->to_br_session());
        m_info("Set SSL session!", func_name);
    }
    
    int ret = br_ssl_client_reset(&m_sslctx, host, 1);
    if (!ret) {
        m_error("Reset of bearSSL failed", func_name);
        m_print_br_error(br_ssl_engine_last_error(&m_sslctx.eng), SSL_ERROR);
        setWriteError(SSL_BR_CONNECT_FAIL);
        return 0;
    }

    if (m_insecure_mode) {
        m_warn("WARNING: INSECURE mode. Verification disabled.", func_name);
        br_ssl_engine_set_x509(&m_sslctx.eng, (const br_x509_class **)&m_insecure_context);
    } else {
        br_ssl_engine_set_x509(&m_sslctx.eng, &m_x509ctx.vtable);
    }

    if (m_run_until(BR_SSL_SENDAPP) < 0) {
		m_error("Failed to initlalize the SSL layer", func_name);
        m_print_br_error(br_ssl_engine_last_error(&m_sslctx.eng), SSL_ERROR);
        return 0;
	}
    m_info("Connection successful!", func_name);
    m_is_connected = true;
    if (ssl_ses != nullptr)
        br_ssl_engine_get_session_parameters(&m_sslctx.eng, ssl_ses->to_br_session());
    else if (host != nullptr) {
        if (m_sessions.size() >= m_max_sessions)
            m_sessions.erase(m_sessions.begin());
        SSLSession session(host);
        br_ssl_engine_get_session_parameters(&m_sslctx.eng, session.to_br_session());
        m_sessions.push_back(session);
    }
    return 1;
}

int SSLClient::m_run_until(const unsigned target) {
    const char* func_name = __func__;
    unsigned lastState = 0;
    //size_t lastLen = 0;
    const unsigned long start = millis();
    for (;;) {
        // --- FIX CRITICO PARA S2: yield() ---
        yield(); 
        // ------------------------------------
        
        unsigned state = m_update_engine();
        if (state == BR_SSL_CLOSED || getWriteError() != SSL_OK) {
            if (state == BR_SSL_CLOSED) {
                m_warn("Terminating because the ssl engine closed", func_name);
            }
            else {
                m_warn("Terminating with write error: ", func_name);
                m_warn(getWriteError(), func_name);
            }
            return -1;
        }
        if (millis() - start > getTimeout()) {
            m_error("SSL internals timed out!", func_name);
            setWriteError(SSL_BR_WRITE_ERROR);
            stop();
            return -1;
        }
        if (state != lastState || lastState == 0) {
            lastState = state;
        }
        if (state & BR_SSL_RECVREC) {
            size_t len;
            br_ssl_engine_recvrec_buf(&m_sslctx.eng, &len);
        }
		if (state & target || (target == 0 && state == 0)) return 0;

		if (state & BR_SSL_RECVAPP && target & BR_SSL_SENDAPP) {
            size_t len;
            if (br_ssl_engine_recvapp_buf(&m_sslctx.eng, &len) != nullptr) {
                m_write_idx = 0;
                m_warn("Discarded unread data to favor a write operation", func_name);
                br_ssl_engine_recvapp_ack(&m_sslctx.eng, len);
                continue;
            }
            else {
                m_error("SSL engine state is RECVAPP, however the buffer was null!", func_name);
                setWriteError(SSL_BR_WRITE_ERROR);
                stop();
                return -1;
            }
        }
		if (state & BR_SSL_SENDAPP && target & BR_SSL_RECVAPP) br_ssl_engine_flush(&m_sslctx.eng, 0);
    }
}

unsigned SSLClient::m_update_engine() {
    const char* func_name = __func__;
    for(;;) {
        unsigned state = br_ssl_engine_current_state(&m_sslctx.eng);
        if (m_br_last_state == 0 || state != m_br_last_state) {
            m_br_last_state = state;
        }
        if (state & BR_SSL_CLOSED) return state;
        if (state & BR_SSL_SENDREC) {
            unsigned char *buf;
            size_t len;
            int wlen;

            buf = br_ssl_engine_sendrec_buf(&m_sslctx.eng, &len);
            wlen = get_arduino_client().write(buf, len);
            get_arduino_client().flush();
            if (wlen <= 0) {
                if (get_arduino_client().getWriteError() || !get_arduino_client().connected()) {
                    m_error("Error writing to m_client", func_name);
                    m_error(get_arduino_client().getWriteError(), func_name);
                    setWriteError(SSL_CLIENT_WRTIE_ERROR);
                }
                stop();
                return 0;
            }
            if (wlen > 0) {
                br_ssl_engine_sendrec_ack(&m_sslctx.eng, wlen);
            }
	    continue;
        }
        
        if (m_write_idx > 0) {
            if (!(state & BR_SSL_SENDAPP)) {
                m_error("Error m_write_idx > 0 but the ssl engine is not ready for data", func_name);
                m_error(br_ssl_engine_current_state(&m_sslctx.eng), func_name);
                m_error(br_ssl_engine_last_error(&m_sslctx.eng), func_name);
                setWriteError(SSL_BR_WRITE_ERROR);
                stop();
                return 0;
            }
            else if (state & BR_SSL_SENDAPP) {
	            size_t alen;
                unsigned char *buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
                if (alen == 0 || buf == nullptr) {
                    m_error("Engine set write flag but returned null buffer", func_name);
                    setWriteError(SSL_BR_WRITE_ERROR);
                    stop();
                    return 0;
                }
                if (alen < m_write_idx) {
                    m_error("Alen is less than m_write_idx", func_name);
                    setWriteError(SSL_INTERNAL_ERROR);
                    stop();
                    return 0;
                }
                br_ssl_engine_sendapp_ack(&m_sslctx.eng, m_write_idx);
                m_write_idx = 0;
                continue;
            }
        }
        
        if (state & BR_SSL_RECVREC) {
			size_t len;
			unsigned char * buf = br_ssl_engine_recvrec_buf(&m_sslctx.eng, &len);
            const auto avail = get_arduino_client().available();
            if (avail > 0) {
                int rlen = get_arduino_client().read(buf, avail < len ? avail : len);
                if (rlen <= 0) {
                    m_error("Error reading bytes from m_client. Write Error: ", func_name);
                    m_error(get_arduino_client().getWriteError(), func_name);
                    setWriteError(SSL_CLIENT_WRTIE_ERROR);
                    stop();
                    return 0;
                }
                if (rlen > 0) {
                    br_ssl_engine_recvrec_ack(&m_sslctx.eng, rlen);
                }
                continue;
            }
			else {
                delay(10);
                return state;
            }
        }
        return state;
    }
}

int SSLClient::m_get_session_index(const char* host) const {
    const char* func_name = __func__;
    if(host == nullptr) return -1;
    for (uint8_t i = 0; i < getSessionCount(); i++) {
        if (m_sessions[i].get_hostname().equals(host)) {
            m_info(m_sessions[i].get_hostname(), func_name);
            return i;
        }
    }
    return -1;
}

void SSLClient::m_print_prefix(const char* func_name, const DebugLevel level) const {
    Serial.print("(SSLClient)");
    switch (level) {
        case SSL_INFO: Serial.print("(SSL_INFO)"); break;
        case SSL_WARN: Serial.print("(SSL_WARN)"); break;
        case SSL_ERROR: Serial.print("(SSL_ERROR)"); break;
        default: Serial.print("(Unknown)");
    }
    Serial.print("(");
    Serial.print(func_name);
    Serial.print("): ");
}

void SSLClient::m_print_ssl_error(const int ssl_error, const DebugLevel level) const {
    if (level > m_debug) return;
    m_print_prefix(__func__, level);
    Serial.println(ssl_error);
}

void SSLClient::m_print_br_error(const unsigned br_error_code, const DebugLevel level) const {
    if (level > m_debug) return;
    m_print_prefix(__func__, level);
    switch (br_error_code) {
        case BR_ERR_X509_NOT_TRUSTED: Serial.println("Chain not trusted (Cert Issue)"); break;
        case BR_ERR_X509_EXPIRED: Serial.println("Cert expired/invalid time"); break;
        default: Serial.print("BearSSL err: "); Serial.println(br_error_code); break;
    }
}

void SSLClient::m_print_br_state(const unsigned state, const DebugLevel level) const {
    const char* func_name = __func__;
    if (level > m_debug) return;
    m_print_prefix(func_name, level);
    Serial.print("State: "); Serial.println(state);
}