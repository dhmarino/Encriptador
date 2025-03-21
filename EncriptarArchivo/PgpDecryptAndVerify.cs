using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncriptarArchivo
{
    public class PgpDecryptAndVerify
    {
        public static bool DecryptAndVerify(Stream encryptedData, Stream privateKeyStream, Stream publicKeyStream, string passphrase, string outputFilePath)
        {
            bool Verify = false;

            PgpObjectFactory pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(encryptedData));
            PgpEncryptedDataList encDataList = null;
            PgpObject o;

            while ((o = pgpF.NextPgpObject()) != null)
            {
                if (o is PgpEncryptedDataList list)
                {
                    encDataList = list;
                    break;
                }
            }

            if (encDataList == null)
                throw new ArgumentException("No se encontraron datos encriptados.");

            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData encryptedDataObj = null;
            PgpSecretKeyRingBundle pgpSecBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            foreach (PgpPublicKeyEncryptedData pked in encDataList.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>())
            {
                privateKey = FindSecretKey(pgpSecBundle, pked.KeyId, passphrase.ToCharArray());

                if (privateKey != null)
                {
                    encryptedDataObj = pked;
                    break;
                }
            }

            if (privateKey == null)
                throw new ArgumentException("Clave privada incorrecta o no encontrada.");

            using (Stream clearStream = encryptedDataObj.GetDataStream(privateKey))
            {
                PgpOnePassSignatureList onePassSignatures = null;
                PgpLiteralData literalData = null;

                PgpObjectFactory plainFact = new PgpObjectFactory(clearStream);
                PgpObject message;
                try
                {
                    while ((message = plainFact.NextPgpObject()) != null)
                    {
                        Console.WriteLine($"Objeto encontrado: {message.GetType().Name}");

                        if (message is PgpCompressedData compressed)
                        {
                            PgpObjectFactory decompressedFactory = new PgpObjectFactory(compressed.GetDataStream());
                            PgpObject innerMessage;

                            while ((innerMessage = decompressedFactory.NextPgpObject()) != null)
                            {
                                Console.WriteLine($"Objeto dentro de la compresión: {innerMessage.GetType().Name}");

                                if (innerMessage is PgpOnePassSignatureList onePassList)
                                    onePassSignatures = onePassList;

                                if (innerMessage is PgpLiteralData innerLiteral)
                                {
                                    literalData = innerLiteral;
                                    break;  // ⚠️ Salimos del loop una vez que encontramos PgpLiteralData
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error al procesar el archivo PGP: {ex.Message}");
                }


                // Verificar firma después de encontrar PgpLiteralData
                if (onePassSignatures != null && literalData != null)
                {
                    Console.WriteLine("Se encontró la firma y los datos. Procediendo a verificar...");
                    using (Stream outputStream = File.Create(outputFilePath))
                    using (Stream literalStream = literalData.GetInputStream())
                    {
                        Streams.PipeAll(literalStream, outputStream);
                    }
                    Verify = VerifySignature(publicKeyStream, onePassSignatures, plainFact);
                }
                else
                {
                    Console.WriteLine("No se encontró firma en el archivo.");
                }
            }
            return Verify;
        }
        private static bool VerifySignature(Stream publicKeyStream, PgpOnePassSignatureList onePassSignatures, PgpObjectFactory plainFact)
        {
            PgpPublicKeyRingBundle pgpPubBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
            PgpOnePassSignature onePassSignature = onePassSignatures[0];
            PgpPublicKey pubKey = pgpPubBundle.GetPublicKey(onePassSignature.KeyId) ?? throw new Exception("Clave pública para verificar la firma no encontrada.");
            try
            {
                onePassSignature.InitVerify(pubKey);

                PgpObject literalDataObj = plainFact.NextPgpObject();
                if (literalDataObj is PgpLiteralData literalData)
                {
                    using (Stream dIn = literalData.GetInputStream())
                    {
                        int ch;
                        while ((ch = dIn.ReadByte()) >= 0)
                            onePassSignature.Update((byte)ch);
                    }
                }
                return true;
            }
            catch (Exception)
            {
                throw new Exception("No se pudo verificar la firma.");
            }
        }
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] passPhrase)
        {
            PgpSecretKey secretKey = pgpSec.GetSecretKey(keyId);
            return secretKey?.ExtractPrivateKey(passPhrase);
        }
    }
}
