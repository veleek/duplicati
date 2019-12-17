﻿//  Copyright (C) 2015, The Duplicati Team
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
using NUnit.Framework;
using System.IO;
using System.Linq;
using System.Collections.Generic;

namespace Duplicati.UnitTest
{
    [Category("Border")]
    public class BorderTests : BasicSetupHelper
    {
        private readonly string recreatedDatabaseFile = Path.Combine(BASEFOLDER, "recreated-database.sqlite");

        public override void TearDown()
        {
            base.TearDown();

            if (File.Exists(this.recreatedDatabaseFile))
            {
                File.Delete(this.recreatedDatabaseFile);
            }
        }

        [Test]
        public void Run10kNoProgress()
        {
            RunCommands(1024 * 10, modifyOptions: opts => { 
                opts["disable-file-scanner"] = "true"; 
            });
        }

        [Test]
        public void Run10k()
        {
            RunCommands(1024 * 10);
        }

        [Test]
        public void Run10mb()
        {
            RunCommands(1024 * 10, modifyOptions: opts => { 
                opts["blocksize"] = "10mb";
            });
        }

        [Test]
        public void Run100k()
        {
            RunCommands(1024 * 100);
        }

        [Test]
        public void Run12345_1()
        {
            RunCommands(12345);
        }

        [Test]
        public void Run12345_2()
        {
            RunCommands(12345, 1024 * 1024 * 10);
        }

        [Test]
        public void RunNoMetadata()
        {
            RunCommands(1024 * 10, modifyOptions: opts => {
                opts["skip-metadata"] = "true";
            });
        }


        [Test]
        public void RunMD5()
        {
            RunCommands(1024 * 10, modifyOptions: opts => {
                opts["block-hash-algorithm"] = "MD5";
                opts["file-hash-algorithm"] = "MD5";
            });
        }
            
        [Test]
        public void RunSHA384()
        {
            RunCommands(1024 * 10, modifyOptions: opts => {
                opts["block-hash-algorithm"] = "SHA384";
                opts["file-hash-algorithm"] = "SHA384";
            });
        }

        [Test]
        public void RunMixedBlockFile_1()
        {
            RunCommands(1024 * 10, modifyOptions: opts => {
                opts["block-hash-algorithm"] = "MD5";
                opts["file-hash-algorithm"] = "SHA1";
            });
        }

        [Test]
        public void RunMixedBlockFile_2()
        {
            RunCommands(1024 * 10, modifyOptions: opts => {
                opts["block-hash-algorithm"] = "MD5";
                opts["file-hash-algorithm"] = "SHA256";
            });
        }

        [Test]
        public void RunNoIndexFiles()
        {
            RunCommands(1024 * 10, modifyOptions: opts => {
                opts["index-file-policy"] = "None";
            });
        }

        [Test]
        public void RunSlimIndexFiles()
        {
            RunCommands(1024 * 10, modifyOptions: opts => {
                opts["index-file-policy"] = "Lookup";
            });
        }

        [Test]
        public void RunQuickTimestamps()
        {
            RunCommands(1024 * 10, modifyOptions: opts =>
            {
                opts["check-filetime-only"] = "true";
            });
        }

        [Test]
        public void RunFullScan()
        {
            RunCommands(1024 * 10, modifyOptions: opts =>
            {
                opts["disable-filetime-check"] = "true";
            });
        }

        public static Dictionary<string, int> WriteTestFilesToFolder(string targetfolder, int blocksize, int basedatasize = 0)
        {
            if (basedatasize <= 0)
                basedatasize = blocksize * 1024;

            var filenames = new Dictionary<string, int>
            {
                [""] = basedatasize,
                ["-0"] = 0,
                ["-1"] = 1,

                ["-p1"] = basedatasize + 1,
                ["-p2"] = basedatasize + 2,
                ["-p500"] = basedatasize + 500,
                ["-m1"] = basedatasize - 1,
                ["-m2"] = basedatasize - 2,
                ["-m500"] = basedatasize - 500,

                ["-s1"] = blocksize / 4 + 6,
                ["-s2"] = blocksize / 10 + 6,
                ["-l1"] = blocksize * 4 + 6,
                ["-l2"] = blocksize * 10 + 6,

                ["-bm1"] = blocksize - 1,
                ["-b"] = blocksize,
                ["-bp1"] = blocksize + 1
            };

            var data = new byte[filenames.Select(x => x.Value).Max()];

            foreach (var k in filenames)
                File.WriteAllBytes(Path.Combine(targetfolder, "a" + k.Key), data.Take(k.Value).ToArray());

            return filenames;
        }

        private void RunCommands(int blocksize, int basedatasize = 0, Action<Dictionary<string, string>> modifyOptions = null)
        {
            var testopts = TestOptions;
            testopts["blocksize"] = blocksize.ToString() + "b";
            modifyOptions?.Invoke(testopts);

            var filenames = WriteTestFilesToFolder(DATAFOLDER, blocksize, basedatasize);

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts, null))
                c.Backup(new string[] { DATAFOLDER });

            // After the first backup we remove the --blocksize argument as that should be auto-set
            testopts.Remove("blocksize");
            testopts.Remove("block-hash-algorithm");
            testopts.Remove("file-hash-algorithm");

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts.Expand(new { version = 0 }), null))
            {
                c.List("*");
                //Console.WriteLine("In first backup:");
                //Console.WriteLine(string.Join(Environment.NewLine, r.Files.Select(x => x.Path)));
            }

            // Do a "touch" on files to trigger a re-scan, which should do nothing
            //foreach (var k in filenames)
                //if (File.Exists(Path.Combine(DATAFOLDER, "a" + k.Key)))
                    //File.SetLastWriteTime(Path.Combine(DATAFOLDER, "a" + k.Key), DateTime.Now.AddSeconds(5));

            var data = new byte[filenames.Select(x => x.Value).Max()];
            new Random().NextBytes(data);
            foreach(var k in filenames)
                File.WriteAllBytes(Path.Combine(DATAFOLDER, "b" + k.Key), data.Take(k.Value).ToArray());

            using (var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts, null))
            {
                var r = c.Backup(new string[] { DATAFOLDER });
                if (!Library.Utility.Utility.ParseBoolOption(testopts, "disable-filetime-check"))
                {
                    if (r.OpenedFiles != filenames.Count)
                        throw new Exception($"Opened {r.OpenedFiles}, but should open {filenames.Count}");
                    if (r.ExaminedFiles != filenames.Count * 2)
                        throw new Exception($"Examined {r.ExaminedFiles}, but should examine open {filenames.Count * 2}");
                }
            }

            var rn = new Random();
            foreach(var k in filenames)
            {
                rn.NextBytes(data);
                File.WriteAllBytes(Path.Combine(DATAFOLDER, "c" + k.Key), data.Take(k.Value).ToArray());
            }
            
            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts, null))
                c.Backup(new string[] { DATAFOLDER });
            
            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts.Expand(new { version = 0 }), null))
            {
                var r = c.List("*");
                //ProgressWriteLine("Newest before deleting:");
                //ProgressWriteLine(string.Join(Environment.NewLine, r.Files.Select(x => x.Path)));
                Assert.AreEqual((filenames.Count * 3) + 1, r.Files.Count());
            }

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts.Expand(new { version = 0, no_local_db = true }), null))
            {
                var r = c.List("*");
                //ProgressWriteLine("Newest without db:");
                //ProgressWriteLine(string.Join(Environment.NewLine, r.Files.Select(x => x.Path)));
                Assert.AreEqual((filenames.Count * 3) + 1, r.Files.Count());
            }

            testopts["dbpath"] = this.recreatedDatabaseFile;

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts, null))
                c.Repair();

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts, null))
                Assert.AreEqual(3, c.List().Filesets.Count());

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts.Expand(new { version = 2 }), null))
            {
                var r = c.List("*");
                //ProgressWriteLine("V2 after delete:");
                //ProgressWriteLine(string.Join(Environment.NewLine, r.Files.Select(x => x.Path)));
                Assert.AreEqual((filenames.Count * 1) + 1, r.Files.Count());
            }

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts.Expand(new { version = 1 }), null))
            {
                var r = c.List("*");
                //ProgressWriteLine("V1 after delete:");
                //ProgressWriteLine(string.Join(Environment.NewLine, r.Files.Select(x => x.Path)));
                Assert.AreEqual((filenames.Count * 2) + 1, r.Files.Count());
            }

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts.Expand(new { version = 0 }), null))
            {
                var r = c.List("*");
                //ProgressWriteLine("Newest after delete:");
                //ProgressWriteLine(string.Join(Environment.NewLine, r.Files.Select(x => x.Path)));
                Assert.AreEqual((filenames.Count * 3) + 1, r.Files.Count());
            }

            using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts.Expand(new { restore_path = RESTOREFOLDER, no_local_blocks = true }), null))
            {
                var r = c.Restore(null);
                Assert.AreEqual(filenames.Count * 3, r.RestoredFiles);
            }

            TestUtils.VerifyDir(DATAFOLDER, RESTOREFOLDER, !Library.Utility.Utility.ParseBoolOption(testopts, "skip-metadata"));

            using(var tf = new Library.Utility.TempFolder())
            {
                using(var c = new Library.Main.Controller("file://" + TARGETFOLDER, testopts.Expand(new { restore_path = (string)tf, no_local_blocks = true }), null))
                {
                    var r = c.Restore(new string[] { Path.Combine(DATAFOLDER, "a") + "*" });
                    Assert.AreEqual(filenames.Count, r.RestoredFiles);
                }
            }
        }
    }
}

