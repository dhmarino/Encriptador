using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EncriptarArchivo
{
    public static class PgpDecrypt
    {
        //Se probo para llave RSA y ECDSA/EdDSA
        public static bool DecryptFile(string inputFilePath, string outputFilePath, string privateKeyPath, string passphrase)
        {
            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream keyIn = File.OpenRead(privateKeyPath))
            using (Stream outputStream = File.Create(outputFilePath))
            {
                bool error = DecryptFile(inputStream, outputStream, keyIn, passphrase.ToCharArray());
                return error;
            }
        }
        private static bool DecryptFile(
                Stream inputStream,
                Stream outputStream,
                Stream privateKeyStream,
                char[] passPhrase)
        {
            //Banderas
            bool error = false;

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
            PgpEncryptedDataList enc;

            PgpObject o = pgpF.NextPgpObject();
            if (o is PgpEncryptedDataList list)
            {
                enc = list;
            }
            else
            {
                enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
            }

            PgpPrivateKey sKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>())
            {
                try
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase);
                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }
                catch (Exception)
                {
                    MessageBox.Show("La contraseña es incorrecta");
                    error = true;
                    return error;
                }
            }

            if (sKey == null)
            {
                throw new ArgumentException("La llave secreta no corresponde al archivo");
            }
            Stream clear = pbe.GetDataStream(sKey);
            PgpObjectFactory plainFact = new PgpObjectFactory(clear);

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData cData)
            {
                PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

                message = pgpFact.NextPgpObject();
            }

            if (message is PgpLiteralData ld)
            {
                Stream unc = ld.GetInputStream();
                Streams.PipeAll(unc, outputStream);
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }

            if (pbe.IsIntegrityProtected() && !pbe.Verify())
            {
                throw new PgpException("Message failed integrity check.");
            }
            return error;

        }
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] passPhrase)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(passPhrase);
        }
    }
}
