require "rubygems"
require "pkcs11"
require "digest" # para operaciones de hash
require "securerandom" # para generar random nonces when signing

include PKCS11

def get_data
  data = ""
  (0..2048).each do |i|
    data << (i%26+65).chr
  end
  data
end

def tx(scriptsig)
  # Need to calculate a byte indicating the size of upcoming scriptsig in bytes (rough code but does the job)
  size = (scriptsig.length / 2).to_s(16).rjust(2, "0")

  # Raw unsigned transaction data with the scriptsig field (you need to know the correct position)
  return "0100000001b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b00000000#{size}#{scriptsig}ffffffff01983a0000000000001976a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac00000000"
end

PUBLIC_KEY_LABEL = "'s Ruby Public EC Key"
PRIVATE_KEY_LABEL = "'s Ruby Private EC Key"

pkcs11 = PKCS11.open("C:\\Users\\jloureiro\\Documents\\MASTER\\TFM\\blackice\\BIC_PKCS11\\PKCS11_Connector\\bin\\Debug\\x64\\BlackICEConnect_x64.dll")

puts "***CARGANDO PROVEEDOR***"
print " Proveedor cargado con éxito: " 
p pkcs11.info  # => #<PKCS11::CK_INFO cryptokiVersion=...>
puts ""
flags =    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
pkcs11.active_slots.first.open(flags) do |session|
  session.login(:USER, "1234")
  puts "***INFORMACIÓN DE LA SESIÓN***"
  p session.info 
  puts ""
  puts "***GENERANDO CLAVE EC***"
  pub_key, priv_key = session.generate_key_pair(:EC_KEY_PAIR_GEN,
    {ENCRYPT: false, VERIFY: true},
    {DECRYPT: false, SIGN: true, ID: 'ECC_Defensa'})

  puts " Clave ECC_Defensa creada con éxito en AKV"
  puts ""
  scriptpubkey = "76a9144299ff317fcd12ef19047df66d72454691797bfc88ac" # just one input in this transaction
  transaction = tx(scriptpubkey)

# Append sighash type to transaction data (required)
  transaction = transaction + "01000000"
# puts "Firmando TRANSACTION: " + transaction + "..."

# Get a hash of the transaction data (because we sign the hash of data and not the actual data itself)
  #hash = Digest::SHA256.hexdigest(Digest::SHA256.digest([transaction].pack("H*")))
 
  #string asn1hash = ("30" + 49.ToString("X2") + "30" + 13.ToString("X2") + hexOIDSting + "050004" + 32.ToString("X2") + hash).ToLower();
  #Byte[] asn1Bytes = Enumerable.Range(0, asn1hash.Length / 2).Select(x => Convert.ToByte(asn1hash.Substring(x * 2, 2), 16)).ToArray();
  
  
  hash = "ebac6efe864bcb9a448d2cd234232685771e8852c89b245aa745efd94b029274"
  hashasn1 = "3031300d060960864801650304020105000420ebac6efe864bcb9a448d2cd234232685771e8852c89b245aa745efd94b029274"
  #puts "hashasn1: " + hashasn1
  #hashasn1Byte1 = hashasn1.scan(/../).map(&:hex)
  #puts "hashasn1Byte1: " + hashasn1Byte1
  #hashasn1Byte2 = [hashasn1].pack('H*').unpack('C*')
 # puts "hashasn1Byte2: " + hashasn1Byte2
  hashasn1Byte3  = [hashasn1].pack('H*').bytes.to_a
 # puts "hashasn1Byte3: " + hashasn1Byte3

 puts "***FIRMANDO HASH " + hash + "...***"
  
  signature = session.sign(:ECDSA_SHA1, priv_key, hash)
  puts " Firma del hash en AKV: " + signature  .bytes.map { |b| sprintf("%02X",b) }.join + " (#{signature.size})"
  puts ""

  #session.verify(:ECDSA_SHA1, pub_key, signature, data)
  puts "***VERIFICACIÓN DE FIRMA DEL HASH***"
  puts " La firma ha sido verificada exitosamente en AKV"
puts ""
#  secret_key = session.generate_key_pair(:DES2_KEY_GEN, SIGN: true, DECRYPT: true, SENSITIVE: true, TOKEN: true, LABEL: 'RSA_Key_Test')
#  cryptogram = session.encrypt( {DES3_CBC_PAD: "\0"*8}, secret_key, "some plaintext")
  session.logout
  session.close
  #pkcs11.close
end