using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncriptarArchivo
{
    public class PgpKeyInfo
    {
        public static DateTime? GetKeyExpiration(string publicKeyPath)
        {
            using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
            {
                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));

                foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        DateTime creationTime = key.CreationTime;
                        long validityPeriod = key.GetValidSeconds(); // Validity period in seconds

                        if (validityPeriod == 0)
                        {
                            // The key does not expire
                            return null;
                        }
                        else
                        {
                            // Calculate the expiration time
                            DateTime expirationTime = creationTime.AddSeconds(validityPeriod);
                            return expirationTime;
                        }
                    }
                }
            }
            throw new ArgumentException("No valid keys found in the public key file.");
        }
        public static long GetKeyId(string publicKeyPath)
        {
            using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
            {
                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));

                foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        long keyId = key.KeyId;
                        return (keyId);
                    }
                }
            }
            throw new ArgumentException("No valid keys found in the public key file.");
        }
    }
}
