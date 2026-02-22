function [is_correct] = verify(key10,initial_value,expected_result)
%VERIFY Permet de vérifier si l'hypothèse de clé est correcte
%   Décrypte le message chiffré avec la clé, et compare le résultat avec le
%   plaintext original, a besoin de gf() pour les corps de Galois, renvoie
%   true si la clé est correcte, et false dans le cas contraire
arguments (Input)
    key10
    initial_value
    expected_result
end

arguments (Output)
    is_correct
end
warning off;
SBox=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];
invSBox(SBox(1:256)+1)=0:255;

invMC = [14 11 13 9;
    9 14 11 13;
    13 9 14 11;
    11 13 9 14];
invMC_gf = gf(invMC, 8, 283);

tmp = cell(1,11);
[tmp{:}] = decipher_key(key10);
keys = vertcat(tmp{:});
keys = string(reshape(keys,11,2,16));
keys = reshape(keys.',4,4,11);
keys = hex2dec(keys);

init_val = string(reshape(char(initial_value),2,[]).');
init_val = hex2dec(reshape(init_val,4,4));

exp_val = string(reshape(char(expected_result),2,[]).');
exp_val = hex2dec(reshape(exp_val,4,4));

val = bitxor(init_val,keys(:,:,11));
val(4,:) = circshift(val(4,:),3);
val(3,:) = circshift(val(3,:),2);
val(2,:) = circshift(val(2,:),1);
val = invSBox(val+1);

for i = 10:-1:2
    val = bitxor(val,keys(:,:,i)); % Ajout de la Round Key

    for j = 1:4
        col_gf = gf((val(:,j)), 8, 283);       % 283 = 0x11B, polynome irréductible pour l'AES
    
        % Appliquer l'inverse de MixColumns
        result_gf = invMC_gf * col_gf;
        val(:,j) = result_gf.x;
    end
    
    % ShiftRows inversé
    val(4,:) = circshift(val(4,:),3);
    val(3,:) = circshift(val(3,:),2);
    val(2,:) = circshift(val(2,:),1);
    val = invSBox(val+1); % SubBytes inversé
    
    
end
val = bitxor(val,keys(:,:,1));
is_correct = isequal(val, exp_val);