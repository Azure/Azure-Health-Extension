﻿//*****************************************************************************************************
// Copyright (c) Microsoft Corporation and Avyan Consulting Corp. All rights reserved.

// Permission is hereby granted, free of charge, to any person 
// obtaining a copy of this software and associated documentation 
// files (the "Software"), to deal in the Software without restriction, 
// including without limitation the rights to use, copy, modify, merge, 
// publish, distribute, sublicense, and/or sell copies of the Software, 
// and to permit persons to whom the Software is furnished to do so, 
// subject to the following conditions:
// The above copyright notice and this permission notice shall be 
// included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//******************************************************************************************************

namespace HIPAA.Platform.Workflow.Model
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Web;
    using Newtonsoft.Json;

    public class Condition
    {
        [JsonProperty("resourceType")]
        public string ResourceType { get; set; }
        [JsonProperty("id")]
        public int Id { get; set; }
        [JsonProperty("clinicalStatus")]
        public string ClinicalStatus { get; set; }
        [JsonProperty("verificationStatus")]
        public string VerificationStatus { get; set; }
        [JsonProperty("code")]
        public Code Code { get; set; }
        [JsonProperty("subject")]
        public Subject Subject { get; set; }
    }
}