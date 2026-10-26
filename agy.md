Thought for 4s, 284 tokens
Everything compiled without errors, enabling a detailed Portuguese explanation of the code's modifications. Focused on outlining the diagnosed issues, developed solutions, and complet...
Todo o desenvolvimento pendente no código foi concluído e validado com sucesso. Abaixo encontra-se o resumo detalhado das correções, implementações de segurança e testes realizados.   

### 1. Diagnóstico e Problemas Resolvidos no Código

1. Gestão de Fornecedores Criptográficos (BouncyCastle):                                                                                                                                
   • As classes de cifra do BouncyCastle (RC6, CCM, etc.) não estavam a ser devidamente registadas no runtime, resultando em erros como Cannot find any provider supporting            
   RC6/GCM/NoPadding.                                                                                                                                                                  
   • Adicionou-se o registo estático e idempotente do BouncyCastleProvider em CryptoService.java e CryptoConfig.java.
2. Deteção de Cifras AEAD vs. Modos Clássicos:                                                                                                                                          
   • Em CryptoConfig.java, a verificação isAead() falhava para ChaCha20-Poly1305 porque a combinação Algorithm=ChaCha20 e Mode=Poly1305 era incorretamente encaminhada para cifra      
   clássica com IV de 16 bytes (quando Poly1305 exige nonce de 12 bytes / 96 bits).                                                                                                    
   • Corrigiu-se a identificação de AEAD para incluir GCM, CCM, Poly1305 e ChaCha20-Poly1305.                                                                                          
   • Suportou-se o modo puro de cifra de fluxo ChaCha20 com parâmetros ChaCha20ParameterSpec e nonces de 12 bytes.
3. Flexibilidade e Parsing de Ficheiros de Configuração XML:                                                                                                                            
   • Suporte transparente para chaves em formato Hexadecimal e Base64 em CryptoConfig.java.                                                                                            
   • Normalização de tags XML (tratamento case-insensitive para tags como <KeySize>, <Keysize>, <IVSize>, etc.).                                                                       
   • Normalização de nomes de algoritmo MAC (ex: HMAC-SHA-512 do PDF normalizado para HmacSHA512).                                                                                     
   • Localização automática de ficheiros de configuração com caminhos relativos em pastas de fallback.
4. Garantias de Segurança no Protocolo (StreamServer.java e ProxySocketServer.java):                                                                                                    
   • Proteção contra Replay Attacks: Implementação de cache thread-safe no servidor para registo de nonces SECX da mensagem Tipo 1. Reenvios de mensagens Tipo 1 capturadas são        
   imediatamente rejeitados com alerta Tipo 255.                                                                                                                                       
   • Validação de Sequência Monotónica: O proxy verifica estritamente se cada bloco de streaming cumpre type4.seqb() == expectedSeq. Saltos de sequência, blocos em falta ou blocos    
   duplicados acionam alerta imediato e encerram a sessão.                                                                                                                             
   • Proteção contra Truncagem de Stream (Stream Truncation Attack): O bloco final Tipo 5 encapsula cifrado o identificador SEQF == expectedSeq e o sinal "END". O proxy desencapsula e
   valida a terminação correta antes de encerrar o stream.                                                                                                                             
   • Integridade & Autenticidade (MITM Tampering): Nos modos AEAD o tag de 128 bits é verificado; nos modos clássicos é aplicado Encrypt-then-MAC (IV || Ciphertext) com validação de  
   tempo constante MessageDigest.isEqual. Qualquer alteração de 1 bit desencadeia exceção e alerta Tipo 255.                                                                           
   • Autenticação do Handshake: Validação estrita do desafio SRV com R = SHA-256(SRV) e confirmação de configuração criptográfica CCC.

──────
### 2. Suites de Configuração Criadas

Foram criados 10 ficheiros de configuração em WA1-Materials/configs/:

| Ficheiro  | Algoritmo | Modo | Padding | Integridade / MAC
| --- | --- | --- | --- | ---
| aes-gcm.xml | AES-256 | GCM | None | AEAD 
| aes-ccm.xml | AES-256  | CCM | None | AEAD 
| chacha20-poly1305.xml | ChaCha20 | Poly1305 | None | AEAD
| rc6-gcm.xml | RC6-256 | GCM | None | AEAD
| aes-ctr-hmac.xml | AES-256 | CTR | NoPadding | HMAC-SHA256
| aes-cbc-hmac.xml |AES-256  | CBC | PKCS5Padding | HMAC-SHA256
| aes-ecb-hmac.xml | AES-256 | ECB | PKCS5Padding | HMAC-SHA256
| rc6-ctr-hmac.xml | RC6-256 | CTR | NoPadding | HMAC-SHA256
| rc6-cbc-hmac.xml | RC6-256 | CBC | PKCS5Padding | HMAC-SHA256
| chacha20-hmac.xml | ChaCha20 | NULL | None | HMAC-SHA256

### 3. Validação e Testes Experimentais

Foram desenvolvidos três testbenches automatizados em WA1-Materials/scratch/:

1. Testbench de Segurança do Modelo de Ameaças (IntegrationSecurityTestbench):                                                                                                          
   • End-to-End Streaming: 1534 blocos recebidos e decifrados, hash SHA-256 71944d7430c461f0cd6e7fd10cee7eb72786352a3678fc7bc0ae3d410f72aece validada a 100%.                          
   • Replay Attack: Servidor rejeitou SECX reutilizado: "Replay attack detected: SECX nonce already used".                                                                             
   • Tampering Attack: 1 bit alterado no bloco cifrado → intercetado com AEADBadTagException / SecurityException.                                                                      
   • Incompatible Policy: Rejeição de cifras não autorizadas com alerta Tipo 255.                                                                                                      
   • Forged Challenge Response: Resposta R falsa rejeitada com alerta Tipo 255.                                                                                                        
   • Message-Ordering: Deteção imediata de salto ou duplicação de blocos.                                                                                                              
   • Resultado: 6 / 6 Testes Aprovados.
2. Testbench Multi-Configurações (MultiConfigTestbench):                                                                                                                                
   • Teste automatizado de todas as 10 suites criptográficas com validação de integridade por hash SHA-256.                                                                            
   • Resultado: 10 / 10 Suites Aprovadas (100% Interoperabilidade).
3. Testbench de Concorrência e Paralelismo (ConcurrencyTestbench):                                                                                                                      
   • 8 instâncias de proxy em paralelo a descarregar sample.mp4 simultaneamente do mesmo StreamServer.                                                                                 
   • Resultado: 8 / 8 Clientes concluídos com sucesso em 1974 ms sem colisões ou corrupção de dados.

──────
### 4. Documentação e Relatório Técnico

• Instruções de Execução Atualizadas: O ficheiro README.md foi reescrito com comandos precisos de compilação, execução e parametrização.                                                
• Relatório Técnico do Projeto: Criou-se o documento estruturado REPORT.md seguindo a estrutura académica requerida (Springer/FAQ):                                                     
1. Introduction                                                                                                                                                                     
2. System model and architectural design                                                                                                                                            
3. Threat model definition and security countermeasures (tabela de mapeamento completa)                                                                                             
4. Specification of the Secure Streaming Protocol (diagrama Mermaid e formatos binários)                                                                                            
5. Cryptographic configuration files                                                                                                                                                
6. Stream Proxy design and implementation options                                                                                                                                   
7. Server Stream design and implementation options                                                                                                                                  
8. Validation & Experimental observations                                                                                                                                           
9. Conclusions