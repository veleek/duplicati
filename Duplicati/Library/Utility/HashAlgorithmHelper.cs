﻿//  Copyright (C) 2017, The Duplicati Team
//  http://www.duplicati.com, info@duplicati.com
//
//  This library is free software; you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as
//  published by the Free Software Foundation; either version 2.1 of the
//  License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

using System;

namespace Duplicati.Library.Utility
{
    /// <summary>
    /// This class helps picking the fastest hash algorithm implementation,
    /// which is what <seealso cref="System.Security.Cryptography.HashAlgorithm.Create()"/> should do, but does not.
    /// </summary>
    public static class HashAlgorithmHelper
    {
        /// <summary>
        /// Create the hash algorithm with the specified name.
        /// </summary>
        /// <returns>The hash algorithm.</returns>
        /// <param name="name">The name of the algorithm to create.</param>
        public static System.Security.Cryptography.HashAlgorithm Create(string name)
        {
            System.Security.Cryptography.SHA256 hasher;
            try
            {
                // TODO: right now it will always use SHA256
                // "SHA1", "MD5", "SHA256", "SHA384", "SHA512"
                hasher = new System.Security.Cryptography.SHA256Managed();
                //var hasher = System.Security.Cryptography.HashAlgorithm.Create(name);
            }
            catch (PlatformNotSupportedException)
            {
                hasher = System.Security.Cryptography.SHA256.Create();
            }
            return hasher;
        }
    }
}
