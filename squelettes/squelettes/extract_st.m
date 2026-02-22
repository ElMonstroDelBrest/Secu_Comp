clear all;
clc;
close all;

folderSrc = ' ?????? ';

% Number of traces
%Nt = 10; 
Nt = 20000;
matrixFilelist = dir(folderSrc);

% get the size of the filelist
sizeFilelist = size(matrixFilelist,1);
Nti=0;
for i = 1:sizeFilelist
	Nti = Nti+1;
        key(Nti,:) =  ????;
	pti(Nti,:) =  ????;
        cto(Nti,:) = ????;
end

for i = 1:size(key,1)
       key_dec(i,:)= ?????;
       pti_dec(i,:)= ?????; 
       cto_dec(i,:)= ?????;    
end

save('key_dec.mat','key_dec')
save('pti_dec.mat','pti_dec')
save('cto_dec.mat','cto_dec')
save('L.mat','L')
