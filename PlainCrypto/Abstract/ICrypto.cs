/* Dev By: Gilberto Hernandez 
 */
using System;

namespace PlainCrypto.Abstract
{
    public interface ICrypto
    {
        string Encrypt(string message);

        string Decrypt(string message);
    }
}
